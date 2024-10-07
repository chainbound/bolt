package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	fastSsz "github.com/ferranbt/fastssz"

	builderApiBellatrix "github.com/attestantio/go-builder-client/api/bellatrix"
	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	consensusSpec "github.com/attestantio/go-eth2-client/spec"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// A wrapper struct over `builderSpec.VersionedSignedBuilderBid`
// to include constraint inclusion proofs
type VersionedSignedBuilderBidWithProofs struct {
	Proofs *InclusionProof
	*builderSpec.VersionedSignedBuilderBid
}

// this is necessary, because the mev-boost-relay deserialization doesn't expect a "Version" and "Data" wrapper object
// for deserialization. Instead, it tries to decode the object into the "Deneb" version first and if that fails, it tries
// the "Capella" version. This is a workaround to make the deserialization work.
//
// NOTE(bolt): struct embedding of the VersionedSubmitBlockRequest is not possible for some reason because it causes the json
// encoding to omit the `proofs` field. Embedding all of the fields directly does the job.
func (v *VersionedSignedBuilderBidWithProofs) MarshalJSON() ([]byte, error) {
	switch v.Version {
	case consensusSpec.DataVersionBellatrix:
		return json.Marshal(struct {
			Message   *builderApiBellatrix.BuilderBid `json:"message"`
			Signature phase0.BLSSignature             `json:"signature"`
			Proofs    *InclusionProof                 `json:"proofs"`
		}{
			Message:   v.Bellatrix.Message,
			Signature: v.Bellatrix.Signature,
			Proofs:    v.Proofs,
		})
	case consensusSpec.DataVersionCapella:
		return json.Marshal(struct {
			Message   *builderApiCapella.BuilderBid `json:"message"`
			Signature phase0.BLSSignature           `json:"signature"`
			Proofs    *InclusionProof               `json:"proofs"`
		}{
			Message:   v.Capella.Message,
			Signature: v.Capella.Signature,
			Proofs:    v.Proofs,
		})
	case consensusSpec.DataVersionDeneb:
		return json.Marshal(struct {
			Message   *builderApiDeneb.BuilderBid `json:"message"`
			Signature phase0.BLSSignature         `json:"signature"`
			Proofs    *InclusionProof             `json:"proofs"`
		}{
			Message:   v.Deneb.Message,
			Signature: v.Deneb.Signature,
			Proofs:    v.Proofs,
		})
	}

	return nil, fmt.Errorf("unknown data version %d", v.Version)
}

func (v *VersionedSignedBuilderBidWithProofs) String() string {
	return JSONStringify(v)
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
