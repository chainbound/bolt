package builder

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	utilbellatrix "github.com/attestantio/go-eth2-client/util/bellatrix"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	ssz "github.com/ferranbt/fastssz"
)

var errHTTPErrorResponse = errors.New("HTTP error response")

func DecodeConstraints(constraints *common.SignedConstraints) (types.HashToConstraintDecoded, error) {
	decodedConstraints := make(types.HashToConstraintDecoded)
	for _, tx := range constraints.Message.Constraints {
		decoded := new(types.Transaction)
		if err := decoded.UnmarshalBinary(tx.Tx); err != nil {
			return nil, err
		}
		decodedConstraints[decoded.Hash()] = &types.ConstraintDecoded{Index: tx.Index, Tx: decoded}
	}
	return decodedConstraints, nil
}

// SendSSZRequest is a request to send SSZ data to a remote relay.
func SendSSZRequest(ctx context.Context, client http.Client, method, url string, payload []byte, useGzip bool) (code int, err error) {
	var req *http.Request

	reader := bytes.NewReader(payload)

	if useGzip {
		// Create a new gzip writer
		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)

		// Write the payload to the gzip writer
		_, err = reader.WriteTo(gzipWriter)
		if err != nil {
			return 0, fmt.Errorf("error writing payload to gzip writer: %w", err)
		}

		// Flush and close the gzip writer to finalize the compressed data
		err = gzipWriter.Close()
		if err != nil {
			return 0, fmt.Errorf("error closing gzip writer: %w", err)
		}

		req, err = http.NewRequest(http.MethodPost, url, &buf)
		if err != nil {
			return 0, fmt.Errorf("error creating request: %w", err)
		}
		req.Header.Add("Content-Encoding", "gzip")
	} else {
		req, err = http.NewRequest(http.MethodPost, url, reader)
		if err != nil {
			return 0, fmt.Errorf("error creating request: %w", err)
		}
	}

	req.Header.Add("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read error response body for status code %d: %w", resp.StatusCode, err)
		}
		return resp.StatusCode, fmt.Errorf("HTTP error response: %d / %s", resp.StatusCode, string(bodyBytes))
	}
	return resp.StatusCode, nil
}

// SendHTTPRequest - prepare and send HTTP request, marshaling the payload if any, and decoding the response if dst is set
func SendHTTPRequest(ctx context.Context, client http.Client, method, url string, payload, dst any) (code int, err error) {
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

// EmitBoltDemoEvent sends a message to the web demo backend to log an event.
// This is only used for demo purposes and should be removed in production.
func EmitBoltDemoEvent(message string) {
	event := strings.NewReader(fmt.Sprintf("{ \"message\": \"BOLT-BUILDER: %s\"}", message))
	eventRes, err := http.Post("http://host.docker.internal:3001/events", "application/json", event)
	if err != nil {
		log.Error("Failed to send web demo event: ", err)
	}
	if eventRes != nil {
		defer eventRes.Body.Close()
	}
}

func CalculateMerkleMultiProofs(
	payloadTransactions types.Transactions,
	HashToConstraintDecoded types.HashToConstraintDecoded,
) (inclusionProof *common.InclusionProof, rootNode *ssz.Node, err error) {
	constraintsOrderedByIndex, constraintsWithoutIndex, _, _ := types.ParseConstraintsDecoded(HashToConstraintDecoded)
	constraints := slices.Concat(constraintsOrderedByIndex, constraintsWithoutIndex)

	// BOLT: generate merkle tree from payload transactions (we need raw RLP bytes for this)
	rawTxs := make([]bellatrix.Transaction, len(payloadTransactions))
	for i, tx := range payloadTransactions {
		raw, err := tx.WithoutBlobTxSidecar().MarshalBinary()
		if err != nil {
			log.Warn("[BOLT]: could not marshal transaction", "txHash", tx.Hash(), "err", err)
			continue
		}
		rawTxs[i] = bellatrix.Transaction(raw)
	}

	log.Info(fmt.Sprintf("[BOLT]: Generated %d raw transactions for merkle tree", len(rawTxs)))
	bellatrixPayloadTxs := utilbellatrix.ExecutionPayloadTransactions{Transactions: rawTxs}

	rootNode, err = bellatrixPayloadTxs.GetTree()
	if err != nil {
		return nil, nil, fmt.Errorf("could not get tree from transactions: %w", err)
	}

	// BOLT: Set the value of nodes. This is MANDATORY for the proof calculation
	// to output the leaf correctly. This is also never documented in fastssz. -__-
	rootNode.Hash()

	// using our gen index formula: 2 * 2^21 + preconfIndex
	baseGeneralizedIndex := int(math.Pow(float64(2), float64(21)))
	generalizedIndexes := make([]int, len(constraints))
	transactionHashes := make([]common.Hash, len(constraints))

	for i, constraint := range constraints {
		tx := constraint.Tx
		// get the index of the preconfirmed transaction in the block
		preconfIndex := slices.IndexFunc(payloadTransactions, func(payloadTx *types.Transaction) bool { return payloadTx.Hash() == tx.Hash() })
		if preconfIndex == -1 {
			log.Error(fmt.Sprintf("Preconfirmed transaction %s not found in block", tx.Hash()))
			log.Error(fmt.Sprintf("block has %v transactions", len(payloadTransactions)))
			continue
		}

		generalizedIndex := baseGeneralizedIndex + preconfIndex
		generalizedIndexes[i] = generalizedIndex
		transactionHashes[i] = tx.Hash()
	}

	log.Info(fmt.Sprintf("[BOLT]: Calculating merkle multiproof for %d preconfirmed transaction",
		len(constraints)))

	timeStart := time.Now()
	multiProof, err := rootNode.ProveMulti(generalizedIndexes)
	if err != nil {
		return nil, nil, fmt.Errorf("could not calculate merkle multiproof for %d preconf: %w", len(constraints), err)
	}

	timeForProofs := time.Since(timeStart)
	log.Info(fmt.Sprintf("[BOLT]: Calculated merkle multiproof for %d preconf in %s", len(constraints), timeForProofs))

	inclusionProof = common.InclusionProofFromMultiProof(multiProof)
	inclusionProof.TransactionHashes = transactionHashes

	return
}
