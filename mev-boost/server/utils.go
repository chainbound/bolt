package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	fastssz "github.com/ferranbt/fastssz"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/mev-boost/config"
	"github.com/holiman/uint256"
	log "github.com/sirupsen/logrus"
)

const (
	HeaderKeySlotUID = "X-MEVBoost-SlotID"
	HeaderKeyVersion = "X-MEVBoost-Version"
)

var (
	errHTTPErrorResponse  = errors.New("HTTP error response")
	errInvalidForkVersion = errors.New("invalid fork version")
	errMaxRetriesExceeded = errors.New("max retries exceeded")
)

// UserAgent is a custom string type to avoid confusing url + userAgent parameters in SendHTTPRequest
type UserAgent string

// BlockHashHex is a hex-string representation of a block hash
type BlockHashHex string

// SendHTTPRequest - prepare and send HTTP request, marshaling the payload if any, and decoding the response if dst is set
func SendHTTPRequest(ctx context.Context, client http.Client, method, url string, userAgent UserAgent, headers map[string]string, payload, dst any) (code int, err error) {
	var req *http.Request

	if payload == nil {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		if err2 != nil {
			return 0, fmt.Errorf("could not marshal request: %w", err2)
		}
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payloadBytes))

		// Set headers
		req.Header.Add("Content-Type", "application/json")
	}
	if err != nil {
		return 0, fmt.Errorf("could not prepare request: %w", err)
	}

	// Set user agent header
	req.Header.Set("User-Agent", strings.TrimSpace(fmt.Sprintf("mev-boost/%s %s", config.Version, userAgent)))

	// Set other headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}

	if resp.StatusCode > 299 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read error response body for status code %d: %w", resp.StatusCode, err)
		}
		return resp.StatusCode, fmt.Errorf("%w: %d / %s", errHTTPErrorResponse, resp.StatusCode, string(bodyBytes))
	}

	if dst != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read response body: %w", err)
		}

		if err := json.Unmarshal(bodyBytes, dst); err != nil {
			return resp.StatusCode, fmt.Errorf("could not unmarshal response %s: %w", string(bodyBytes), err)
		}
	}

	return resp.StatusCode, nil
}

// SendHTTPRequestWithRetries - prepare and send HTTP request, retrying the request if within the client timeout
func SendHTTPRequestWithRetries(ctx context.Context, client http.Client, method, url string, userAgent UserAgent, headers map[string]string, payload, dst any, maxRetries int, log *log.Entry) (code int, err error) {
	var requestCtx context.Context
	var cancel context.CancelFunc
	if client.Timeout > 0 {
		// Create a context with a timeout as configured in the http client
		requestCtx, cancel = context.WithTimeout(context.Background(), client.Timeout)
	} else {
		requestCtx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	attempts := 0
	for {
		attempts++
		if requestCtx.Err() != nil {
			return 0, fmt.Errorf("request context error after %d attempts: %w", attempts, requestCtx.Err())
		}
		if attempts > maxRetries {
			return 0, errMaxRetriesExceeded
		}

		code, err = SendHTTPRequest(ctx, client, method, url, userAgent, headers, payload, dst)
		if err != nil {
			log.WithError(err).Warn("error making request to relay, retrying")
			time.Sleep(100 * time.Millisecond) // note: this timeout is only applied between retries, it does not delay the initial request!
			continue
		}
		return code, nil
	}
}

// ComputeDomain computes the signing domain
func ComputeDomain(domainType phase0.DomainType, forkVersionHex, genesisValidatorsRootHex string) (domain phase0.Domain, err error) {
	genesisValidatorsRoot := phase0.Root(common.HexToHash(genesisValidatorsRootHex))
	forkVersionBytes, err := hexutil.Decode(forkVersionHex)
	if err != nil || len(forkVersionBytes) != 4 {
		return domain, errInvalidForkVersion
	}
	var forkVersion [4]byte
	copy(forkVersion[:], forkVersionBytes[:4])
	return ssz.ComputeDomain(domainType, forkVersion, genesisValidatorsRoot), nil
}

// DecodeJSON reads JSON from io.Reader and decodes it into a struct
func DecodeJSON(r io.Reader, dst any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

// GetURI returns the full request URI with scheme, host, path and args.
func GetURI(url *url.URL, path string) string {
	u2 := *url
	u2.User = nil
	u2.Path = path
	return u2.String()
}

// bidResp are entries in the bids cache
type bidResp struct {
	t        time.Time
	response builderSpec.VersionedSignedBuilderBid
	bidInfo  bidInfo
	relays   []RelayEntry
}

// bidRespKey is used as key for the bids cache
type bidRespKey struct {
	slot      uint64
	blockHash string
}

// bidInfo is used to store bid response fields for logging and validation
type bidInfo struct {
	blockHash   phase0.Hash32
	parentHash  phase0.Hash32
	pubkey      phase0.BLSPubKey
	blockNumber uint64
	txRoot      phase0.Root
	value       *uint256.Int
}

func httpClientDisallowRedirects(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func weiBigIntToEthBigFloat(wei *big.Int) (ethValue *big.Float) {
	// wei / 10^18
	fbalance := new(big.Float)
	fbalance.SetString(wei.String())
	ethValue = new(big.Float).Quo(fbalance, big.NewFloat(1e18))
	return
}

func parseBidInfo(bid *builderSpec.VersionedSignedBuilderBid) (bidInfo, error) {
	blockHash, err := bid.BlockHash()
	if err != nil {
		return bidInfo{}, err
	}
	parentHash, err := bid.ParentHash()
	if err != nil {
		return bidInfo{}, err
	}
	pubkey, err := bid.Builder()
	if err != nil {
		return bidInfo{}, err
	}
	blockNumber, err := bid.BlockNumber()
	if err != nil {
		return bidInfo{}, err
	}
	txRoot, err := bid.TransactionsRoot()
	if err != nil {
		return bidInfo{}, err
	}
	value, err := bid.Value()
	if err != nil {
		return bidInfo{}, err
	}
	bidInfo := bidInfo{
		blockHash:   blockHash,
		parentHash:  parentHash,
		pubkey:      pubkey,
		blockNumber: blockNumber,
		txRoot:      txRoot,
		value:       value,
	}
	return bidInfo, nil
}

func checkRelaySignature(bid *builderSpec.VersionedSignedBuilderBid, domain phase0.Domain, pubKey phase0.BLSPubKey) (bool, error) {
	root, err := bid.MessageHashTreeRoot()
	if err != nil {
		return false, err
	}
	sig, err := bid.Signature()
	if err != nil {
		return false, err
	}
	signingData := phase0.SigningData{ObjectRoot: root, Domain: domain}
	msg, err := signingData.HashTreeRoot()
	if err != nil {
		return false, err
	}

	return bls.VerifySignatureBytes(msg[:], sig[:], pubKey[:])
}

func getPayloadResponseIsEmpty(payload *builderApi.VersionedSubmitBlindedBlockResponse) bool {
	switch payload.Version {
	case spec.DataVersionCapella:
		if payload.Capella == nil || payload.Capella.BlockHash == nilHash {
			return true
		}
	case spec.DataVersionDeneb:
		if payload.Deneb == nil || payload.Deneb.ExecutionPayload == nil ||
			payload.Deneb.ExecutionPayload.BlockHash == nilHash ||
			payload.Deneb.BlobsBundle == nil {
			return true
		}
	case spec.DataVersionUnknown, spec.DataVersionPhase0, spec.DataVersionAltair, spec.DataVersionBellatrix:
		return true
	}
	return false
}

// EmitBoltDemoEvent sends a message to the web demo backend to log an event.
// This is only used for demo purposes and should be removed in production.
func EmitBoltDemoEvent(message string) {
	event := strings.NewReader(fmt.Sprintf("{ \"message\": \"BOLT-MEV-BOOST: %s\"}", message))
	eventRes, err := http.Post("http://host.docker.internal:3001/events", "application/json", event)
	if err != nil {
		fmt.Printf("Failed to send web demo event: %v", err)
	}
	if eventRes != nil {
		defer eventRes.Body.Close()
	}
}

func Map[T any, U any](slice []*T, mapper func(el *T) *U) []*U {
	result := make([]*U, len(slice))
	for i, el := range slice {
		result[i] = mapper(el)
	}
	return result
}

func JSONStringify(obj any) string {
	b, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	return string(b)
}

func CalculateMerkleMultiProofs(rootNode *fastssz.Node, constraints []struct {
	tx   Transaction
	hash phase0.Hash32
}) (inclusionProof *InclusionProof, err error) {
	// using our gen index formula: 2 * 2^21 + preconfIndex
	baseGeneralizedIndex := int(math.Pow(float64(2), float64(21)))
	generalizedIndexes := make([]int, len(constraints))
	transactionHashes := make([]phase0.Hash32, len(constraints))
	j := 0

	for i, con := range constraints {
		generalizedIndex := baseGeneralizedIndex + i
		generalizedIndexes[i] = generalizedIndex
		transactionHashes[j] = con.hash
		j++
	}

	log.Info(fmt.Sprintf("[BOLT]: Calculating merkle multiproof for %d preconfirmed transaction",
		len(constraints)))

	timeStart := time.Now()
	multiProof, err := rootNode.ProveMulti(generalizedIndexes)
	if err != nil {
		log.Error(fmt.Sprintf("[BOLT]: could not calculate merkle multiproof for %d preconf %s", len(constraints), err))
		return
	}

	timeForProofs := time.Since(timeStart)
	log.Info(fmt.Sprintf("[BOLT]: Calculated merkle multiproof for %d preconf in %s", len(constraints), timeForProofs))

	inclusionProof = InclusionProofFromMultiProof(multiProof)
	inclusionProof.TransactionHashes = transactionHashes

	return inclusionProof, nil
}
