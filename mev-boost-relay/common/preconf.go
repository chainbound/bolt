package common

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	fastSsz "github.com/ferranbt/fastssz"
	"github.com/sirupsen/logrus"

	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// VersionedSubmitBlockRequestWithProofs is a wrapper struct
// over `builderSpec.VersionedSubmitBlockRequest`
// to include preconfirmation proofs
type VersionedSubmitBlockRequestWithProofs struct {
	Inner *VersionedSubmitBlockRequest `json:"inner"`
	// FIXME: this is not spec-aligned yet https://github.com/chainbound/bolt/issues/55
	Proofs []*PreconfirmationWithProof `json:"proofs"`
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
	Proofs []*PreconfirmationWithProof `json:"proofs"`
}

func (b *BidWithPreconfirmationsProofs) String() string {
	out, err := json.Marshal(b)
	if err != nil {
		return err.Error()
	}
	return string(out)
}

func (p *PreconfirmationWithProof) String() string {
	proofs, err := json.Marshal(p)
	if err != nil {
		return err.Error()
	}
	return string(proofs)
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

// SerializedMerkleProof contains a serialized Merkle proof of transaction inclusion.
//   - `Index“ is the generalized index of the included transaction from the SSZ tree
//     created from the list of transactions.
//   - `Hashes` are the other branch hashes needed to reconstruct the Merkle proof.
//
// For reference, see https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md
type SerializedMerkleProof struct {
	Index  int        `json:"index"`
	Hashes []HexBytes `ssz-size:"dynamic" json:"hashes"`
}

func (s *SerializedMerkleProof) FromFastSszProof(p *fastSsz.Proof) {
	s.Index = p.Index
	s.Hashes = make([]HexBytes, len(p.Hashes))
	for i, h := range p.Hashes {
		s.Hashes[i] = h
	}
}

// ToFastSszProof converts a SerializedMerkleProof to a fastssz.Proof.
func (s *SerializedMerkleProof) ToFastSszProof(leaf []byte) *fastSsz.Proof {
	p := &fastSsz.Proof{
		Index:  s.Index,
		Leaf:   leaf,
		Hashes: make([][]byte, len(s.Hashes)),
	}
	for i, h := range s.Hashes {
		p.Hashes[i] = h
	}
	return p
}

// PreconfirmationWithProof is a preconfirmed transaction in the block with
// proof of inclusion, using Merkle Trees.
type PreconfirmationWithProof struct {
	// The transaction hash of the preconfirmation
	TxHash phase0.Hash32 `ssz-size:"32" json:"txHash"`
	// The Merkle proof of the preconfirmation
	MerkleProof *SerializedMerkleProof `json:"merkleProof"`
}

func NewBoltLogger(service string) *logrus.Entry {
	return LogSetup(false, "info").WithFields(logrus.Fields{
		"service": fmt.Sprintf("BOLT-%s", service),
	})
}
