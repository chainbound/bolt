package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	builderApi "github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2UtilCapella "github.com/attestantio/go-eth2-client/util/capella"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/pkg/errors"
)

var (
	ErrBlockHashMismatch  = errors.New("blockHash mismatch")
	ErrParentHashMismatch = errors.New("parentHash mismatch")

	ErrUnsupportedPayload = errors.New("unsupported payload version")
	ErrNoWithdrawals      = errors.New("no withdrawals")
	ErrPayloadMismatch    = errors.New("beacon-block and payload version mismatch")
	ErrHeaderHTRMismatch  = errors.New("beacon-block and payload header mismatch")
	ErrBlobMismatch       = errors.New("beacon-block and payload blob contents mismatch")
)

func SanityCheckBuilderBlockSubmission(payload *common.VersionedSubmitBlockRequest) error {
	submission, err := common.GetBlockSubmissionInfo(payload)
	if err != nil {
		return err
	}
	if submission.BidTrace.BlockHash.String() != submission.ExecutionPayloadBlockHash.String() {
		return ErrBlockHashMismatch
	}

	if submission.BidTrace.ParentHash.String() != submission.ExecutionPayloadParentHash.String() {
		return ErrParentHashMismatch
	}

	return nil
}

func ComputeWithdrawalsRoot(w []*capella.Withdrawal) (phase0.Root, error) {
	if w == nil {
		return phase0.Root{}, ErrNoWithdrawals
	}
	withdrawals := eth2UtilCapella.ExecutionPayloadWithdrawals{Withdrawals: w}
	return withdrawals.HashTreeRoot()
}

func EqBlindedBlockContentsToBlockContents(bb *common.VersionedSignedBlindedBeaconBlock, payload *builderApi.VersionedSubmitBlindedBlockResponse) error {
	if bb.Version != payload.Version {
		return errors.Wrap(ErrPayloadMismatch, fmt.Sprintf("beacon block version %d does not match payload version %d", bb.Version, payload.Version))
	}

	versionedPayload := &builderApi.VersionedExecutionPayload{ //nolint:exhaustivestruct
		Version: payload.Version,
	}
	switch bb.Version { //nolint:exhaustive
	case spec.DataVersionCapella:
		bbHeaderHtr, err := bb.Capella.Message.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return err
		}

		versionedPayload.Capella = payload.Capella
		payloadHeader, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return err
		}

		payloadHeaderHtr, err := payloadHeader.Capella.HashTreeRoot()
		if err != nil {
			return err
		}

		if bbHeaderHtr != payloadHeaderHtr {
			return ErrHeaderHTRMismatch
		}
	case spec.DataVersionDeneb:
		block := bb.Deneb.Message
		bbHeaderHtr, err := block.Body.ExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return err
		}

		versionedPayload.Deneb = payload.Deneb.ExecutionPayload
		payloadHeader, err := utils.PayloadToPayloadHeader(versionedPayload)
		if err != nil {
			return err
		}

		payloadHeaderHtr, err := payloadHeader.Deneb.HashTreeRoot()
		if err != nil {
			return err
		}

		if bbHeaderHtr != payloadHeaderHtr {
			return ErrHeaderHTRMismatch
		}

		if len(bb.Deneb.Message.Body.BlobKZGCommitments) != len(payload.Deneb.BlobsBundle.Commitments) {
			return errors.Wrap(ErrBlobMismatch, "mismatched number of KZG commitments")
		}

		for i, commitment := range bb.Deneb.Message.Body.BlobKZGCommitments {
			if commitment != payload.Deneb.BlobsBundle.Commitments[i] {
				return errors.Wrap(ErrBlobMismatch, fmt.Sprintf("mismatched KZG commitment at index %d", i))
			}
		}
	default:
		return ErrUnsupportedPayload
	}
	// block and payload are equal
	return nil
}

func checkBLSPublicKeyHex(pkHex string) error {
	_, err := utils.HexToPubkey(pkHex)
	return err
}

func hasReachedFork(slot uint64, forkEpoch int64) bool {
	if forkEpoch < 0 {
		return false
	}
	currentEpoch := slot / common.SlotsPerEpoch
	return currentEpoch >= uint64(forkEpoch)
}

func verifyBlockSignature(block *common.VersionedSignedBlindedBeaconBlock, domain phase0.Domain, pubKey []byte) (bool, error) {
	root, err := block.Root()
	if err != nil {
		return false, err
	}
	sig, err := block.Signature()
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

func getPayloadAttributesKey(parentHash string, slot uint64) string {
	return fmt.Sprintf("%s-%d", parentHash, slot)
}

func broadcastToChannels[T any](constraintsConsumers []chan *T, constraint *T) {
	for _, consumer := range constraintsConsumers {
		consumer <- constraint
	}
}

// validateConstraintSubscriptionAuth checks the authentication string data from the Builder,
// and returns its BLS public key if the authentication is valid.
func validateConstraintSubscriptionAuth(auth string, headSlot uint64) (phase0.BLSPubKey, error) {
	zeroKey := phase0.BLSPubKey{}
	if auth == "" {
		return zeroKey, errors.Errorf("Authorization header missing")
	}
	// Authorization: <auth-scheme> <authorization-parameters>
	parts := strings.Split(auth, " ")
	if len(parts) != 2 {
		return zeroKey, errors.Errorf("Ill-formed authorization header")
	}
	if parts[0] != "BOLT" {
		return zeroKey, errors.Errorf("Not BOLT authentication scheme")
	}
	// <signatureJSON>,<authDataJSON>
	parts = strings.SplitN(parts[1], ",", 2)
	if len(parts) != 2 {
		return zeroKey, errors.Errorf("Ill-formed authorization header")
	}

	signature := new(phase0.BLSSignature)
	if err := signature.UnmarshalJSON([]byte(parts[0])); err != nil {
		fmt.Println("Failed to unmarshal authData: ", err)
		return zeroKey, errors.Errorf("Ill-formed authorization header")
	}

	authDataRaw := []byte(parts[1])
	authData := new(ConstraintSubscriptionAuth)
	if err := json.Unmarshal(authDataRaw, authData); err != nil {
		fmt.Println("Failed to unmarshal authData: ", err)
		return zeroKey, errors.Errorf("Ill-formed authorization header")
	}

	// FIXME: this is broken on the devnet, let's skip it for now
	// if headSlot != authData.Slot {
	// 	return zeroKey, errors.Errorf("Invalid head slot. Expected %d, got %d", headSlot, authData.Slot)
	// }

	ok, err := bls.VerifySignatureBytes(authDataRaw, signature[:], authData.PublicKey[:])
	if err != nil || !ok {
		return zeroKey, errors.Errorf("Invalid signature")
	}
	return authData.PublicKey, nil
}

func JSONStringify[T any](obj T) string {
	out, err := json.Marshal(obj)
	if err != nil {
		return fmt.Sprintf("Error while marshalling: %v", err)
	}
	return string(out)
}

func Find[T any](slice []*T, predicate func(arg *T) bool) *T {
	for _, item := range slice {
		if predicate(item) {
			return item
		}
	}
	return nil
}

// EmitBoltDemoEvent sends a message to the web demo backend to log an event.
// This is only used for demo purposes and should be removed in production.
func EmitBoltDemoEvent(message string) {
	event := strings.NewReader(fmt.Sprintf("{ \"message\": \"BOLT-RELAY: %s\"}", message))
	eventRes, err := http.Post("http://172.17.0.1:3001/events", "application/json", event)
	if err != nil {
		fmt.Printf("Failed to send web demo event: %v", err)
	}
	if eventRes != nil {
		defer eventRes.Body.Close()
	}
}
