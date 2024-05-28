package builder

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/attestantio/go-builder-client/api/bellatrix"
	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-builder-client/api/deneb"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	fastSsz "github.com/ferranbt/fastssz"
)

type HexBytes []byte

// MarshalJSON implements json.Marshaler.
func (h HexBytes) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%#x"`, h)), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (s HexBytes) UnmarshalJSON(input []byte) error {
	if len(input) == 0 {
		return errors.New("input missing")
	}

	if !bytes.HasPrefix(input, []byte{'"', '0', 'x'}) {
		return errors.New("invalid prefix")
	}
	if !bytes.HasSuffix(input, []byte{'"'}) {
		return errors.New("invalid suffix")
	}

	_, err := hex.Decode(s, input[3:len(input)-1])
	if err != nil {
		return err
	}

	return nil
}

// SerializedMerkleProof contains a serialized Merkle proof of transaction inclusion.
//   - `Index` is the generalized index of the included transaction from the SSZ tree
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

func (s *SerializedMerkleProof) ToFastSszProof() *fastSsz.Proof {
	p := &fastSsz.Proof{
		Index:  s.Index,
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

func (p PreconfirmationWithProof) String() string {
	out, err := json.Marshal(p)
	if err != nil {
		return err.Error()
	}
	return string(out)
}

// A wrapper struct over `builderSpec.VersionedSubmitBlockRequest`
// to include preconfirmation proofs
type VersionedSubmitBlockRequestWithPreconfsProofs struct {
	Inner  *builderSpec.VersionedSubmitBlockRequest `json:"inner"`
	Proofs []*PreconfirmationWithProof              `json:"proofs"`
}

// this is necessary, because the mev-boost-relay deserialization doesn't expect a "Version" and "Data" wrapper object
// for deserialization. Instead, it tries to decode the object into the "Deneb" version first and if that fails, it tries
// the "Capella" version. This is a workaround to make the deserialization work.
func (v *VersionedSubmitBlockRequestWithPreconfsProofs) MarshalJSON() ([]byte, error) {
	switch v.Inner.Version {
	case consensusspec.DataVersionBellatrix:
		return json.Marshal(struct {
			Inner  *bellatrix.SubmitBlockRequest `json:"inner"`
			Proofs []*PreconfirmationWithProof   `json:"proofs"`
		}{
			Inner:  v.Inner.Bellatrix,
			Proofs: v.Proofs,
		})
	case consensusspec.DataVersionCapella:
		return json.Marshal(struct {
			Inner  *capella.SubmitBlockRequest `json:"inner"`
			Proofs []*PreconfirmationWithProof `json:"proofs"`
		}{
			Inner:  v.Inner.Capella,
			Proofs: v.Proofs,
		})
	case consensusspec.DataVersionDeneb:
		return json.Marshal(struct {
			Inner  *deneb.SubmitBlockRequest   `json:"inner"`
			Proofs []*PreconfirmationWithProof `json:"proofs"`
		}{
			Inner:  v.Inner.Deneb,
			Proofs: v.Proofs,
		})
	}

	return nil, fmt.Errorf("unknown data version %d", v.Inner.Version)
}

func (v *VersionedSubmitBlockRequestWithPreconfsProofs) String() string {
	out, err := json.Marshal(v)
	if err != nil {
		return err.Error()
	}
	return string(out)
}

// Constraints are a list of proposer constraints that a builder must satisfy
// in order to produce a valid bid.
// Reference: https://chainbound.github.io/bolt-docs/api/builder-api
type Constraints = []*ConstraintSigned

// Reference: https://chainbound.github.io/bolt-docs/api/builder-api
type ConstraintSigned struct {
	Message   ConstraintMessage   `json:"message"`
	Signature phase0.BLSSignature `json:"signature"`
}

// Reference: https://chainbound.github.io/bolt-docs/api/builder-api
type ConstraintMessage struct {
	Constraints    []*Constraint `json:"constraints"`
	ValidatorIndex uint64        `json:"validator_index"`
	Slot           uint64        `json:"slot"`
}

// Reference: https://chainbound.github.io/bolt-docs/api/builder-api
type Constraint struct {
	Index *uint64     `json:"index"`
	Tx    []*HexBytes `json:"tx"`
}
