package common

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// VersionedSubmitBlockRequestWithProofs is a wrapper struct
// over `builderSpec.VersionedSubmitBlockRequest`
// to include preconfirmation proofs
type VersionedSubmitBlockRequestWithProofs struct {
	Inner  *VersionedSubmitBlockRequest `json:"inner"`
	Proofs *InclusionProof              `json:"proofs"`
}

func (v *VersionedSubmitBlockRequestWithProofs) String() string {
	out, err := json.Marshal(v)
	if err != nil {
		return err.Error()
	}
	return string(out)
}

type BidWithPreconfirmationsProofs struct {
	// The block bid
	Bid *builderSpec.VersionedSignedBuilderBid `json:"bid"`
	// The preconfirmations with proofs
	Proofs *InclusionProof `json:"proofs"`
}

func (b *BidWithPreconfirmationsProofs) String() string {
	out, err := json.Marshal(b)
	if err != nil {
		return err.Error()
	}
	return string(out)
}

type HexBytes []byte

// MarshalJSON implements json.Marshaler.
func (h HexBytes) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%#x"`, []byte(h))), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (h *HexBytes) UnmarshalJSON(input []byte) error {
	if len(input) == 0 {
		return errors.New("input missing")
	}

	if !bytes.HasPrefix(input, []byte{'"', '0', 'x'}) {
		return errors.New("invalid prefix")
	}

	if !bytes.HasSuffix(input, []byte{'"'}) {
		return errors.New("invalid suffix")
	}

	var data string
	json.Unmarshal(input, &data)

	res, _ := hex.DecodeString(strings.TrimPrefix(data, "0x"))

	*h = res

	return nil
}

func (h HexBytes) String() string {
	return JSONStringify(h)
}

// InclusionProof is a Merkle Multiproof of inclusion of a set of TransactionHashes
type InclusionProof struct {
	TransactionHashes  []phase0.Hash32 `json:"transaction_hashes"`
	GeneralizedIndexes []uint64        `json:"generalized_indexes"`
	MerkleHashes       []*HexBytes     `json:"merkle_hashes"`
}

func NewBoltLogger(service string) *logrus.Entry {
	return LogSetup(false, "info").WithFields(logrus.Fields{
		"service": fmt.Sprintf("BOLT-%s", service),
	})
}
