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
	Proofs *InclusionProof `json:"proofs"`
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

// InclusionProof is a Merkle Multiproof of inclusion of a set of TransactionHashes
type InclusionProof struct {
	TransactionHashes  []phase0.Hash32 `json:"transaction_hashes"`
	GeneralizedIndexes []uint64        `json:"generalized_indexes"`
	MerkleHashes       []*HexBytes     `json:"merkle_hashes"`
}

// InclusionProofFromMultiProof converts a fastssz.Multiproof into an InclusionProof, without
// filling the TransactionHashes
func InclusionProofFromMultiProof(mp *fastSsz.Multiproof) *InclusionProof {
	merkleHashes := make([]*HexBytes, len(mp.Hashes))
	for i, h := range mp.Hashes {
		merkleHashes[i] = new(HexBytes)
		*(merkleHashes[i]) = h
	}

	leaves := make([]*HexBytes, len(mp.Leaves))
	for i, h := range mp.Leaves {
		leaves[i] = new(HexBytes)
		*(leaves[i]) = h
	}
	generalIndexes := make([]uint64, len(mp.Indices))
	for i, idx := range mp.Indices {
		generalIndexes[i] = uint64(idx)
	}
	return &InclusionProof{
		MerkleHashes:       merkleHashes,
		GeneralizedIndexes: generalIndexes,
	}
}
