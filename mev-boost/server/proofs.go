package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	fastSsz "github.com/ferranbt/fastssz"

	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

type BidWithInclusionProofs struct {
	// The block bid
	Bid *builderSpec.VersionedSignedBuilderBid `json:"bid"`
	// The inclusion proofs
	Proofs []*InclusionProof `json:"proofs"`
}

func (b *BidWithInclusionProofs) String() string {
	out, err := json.Marshal(b)
	if err != nil {
		return err.Error()
	}
	return string(out)
}

func (p *InclusionProof) String() string {
	proofs, err := json.Marshal(p)
	if err != nil {
		return err.Error()
	}
	return string(proofs)
}

type HexBytes []byte

func (h HexBytes) Equal(other HexBytes) bool {
	return bytes.Equal(h, other)
}

// MarshalJSON implements json.Marshaler.
func (h HexBytes) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%#x"`, h)), nil
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

// InclusionProof is a Merkle inclusion proof for a transaction hash.
type InclusionProof struct {
	// The transaction hash of the preconfirmation
	TxHash phase0.Hash32 `ssz-size:"32" json:"txHash"`
	// The Merkle proof of the preconfirmation
	MerkleProof *SerializedMerkleProof `json:"merkleProof"`
}
