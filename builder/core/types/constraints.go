package types

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"

	builderSpec "github.com/attestantio/go-builder-client/spec"
	consensusSpec "github.com/attestantio/go-eth2-client/spec"
	bellatrixSpec "github.com/attestantio/go-eth2-client/spec/bellatrix"
	capellaSpec "github.com/attestantio/go-eth2-client/spec/capella"
	denebSpec "github.com/attestantio/go-eth2-client/spec/deneb"

	"github.com/attestantio/go-builder-client/api/deneb"
	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	ssz "github.com/ferranbt/fastssz"
	"github.com/flashbots/go-boost-utils/bls"
)

var (
	// ConstraintsDomainType is the expected signing domain mask for constraints-API related messages
	ConstraintsDomainType = phase0.DomainType([4]byte{109, 109, 111, 67})
)

// NOTE: given that it uses `common.Hash`, `Transaction` and it's used in both
// the builder package and the miner package, here it's a good place for now

type (
	HashToConstraintDecoded = map[common.Hash]*Transaction
	TransactionEcRecovered  = struct {
		Transaction *Transaction
		Sender      common.Address
	}
)

// ParseConstraintsDecoded receives a map of constraints and returns
// - a slice of constraints sorted by nonce descending and hash descending
// - the total gas required by the constraints
// - the total blob gas required by the constraints
func ParseConstraintsDecoded(constraints HashToConstraintDecoded) ([]*Transaction, uint64, uint64) {
	// Here we initialize and track the constraints left to be executed along
	// with their gas requirements
	constraintsOrdered := make([]*Transaction, 0, len(constraints))
	constraintsTotalGasLeft := uint64(0)
	constraintsTotalBlobGasLeft := uint64(0)

	for _, constraint := range constraints {
		constraintsOrdered = append(constraintsOrdered, constraint)
		constraintsTotalGasLeft += constraint.Gas()
		constraintsTotalBlobGasLeft += constraint.BlobGas()
	}

	// Sorts the unindexed constraints by nonce ascending and by hash
	sort.Slice(constraintsOrdered, func(i, j int) bool {
		iNonce := constraintsOrdered[i].Nonce()
		jNonce := constraintsOrdered[j].Nonce()
		// Sort by hash
		if iNonce == jNonce {
			return constraintsOrdered[i].Hash().Cmp(constraintsOrdered[j].Hash()) > 0 // descending
		}
		return iNonce > jNonce // descending
	})

	return constraintsOrdered, constraintsTotalGasLeft, constraintsTotalBlobGasLeft
}

// InclusionProof is a Merkle Multiproof of inclusion of a set of TransactionHashes
type InclusionProof struct {
	TransactionHashes  []common.Hash      `json:"transaction_hashes"`
	GeneralizedIndexes []uint64           `json:"generalized_indexes"`
	MerkleHashes       []*common.HexBytes `json:"merkle_hashes"`
}

// InclusionProofFromMultiProof converts a fastssz.Multiproof into an InclusionProof, without
// filling the TransactionHashes
func InclusionProofFromMultiProof(mp *ssz.Multiproof) *InclusionProof {
	merkleHashes := make([]*common.HexBytes, len(mp.Hashes))
	for i, h := range mp.Hashes {
		merkleHashes[i] = new(common.HexBytes)
		*(merkleHashes[i]) = h
	}

	leaves := make([]*common.HexBytes, len(mp.Leaves))
	for i, h := range mp.Leaves {
		leaves[i] = new(common.HexBytes)
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

func (p *InclusionProof) String() string {
	return common.JSONStringify(p)
}

// A wrapper struct over `builderSpec.VersionedSubmitBlockRequest`
// to include constraint inclusion proofs
type VersionedSubmitBlockRequestWithProofs struct {
	Proofs *InclusionProof
	*builderSpec.VersionedSubmitBlockRequest
}

// this is necessary, because the mev-boost-relay deserialization doesn't expect a "Version" and "Data" wrapper object
// for deserialization. Instead, it tries to decode the object into the "Deneb" version first and if that fails, it tries
// the "Capella" version. This is a workaround to make the deserialization work.
//
// NOTE(bolt): struct embedding of the VersionedSubmitBlockRequest is not possible for some reason because it causes the json
// encoding to omit the `proofs` field. Embedding all of the fields directly does the job.
func (v *VersionedSubmitBlockRequestWithProofs) MarshalJSON() ([]byte, error) {
	switch v.Version {
	case consensusSpec.DataVersionBellatrix:
		return json.Marshal(struct {
			Message          *v1.BidTrace                    `json:"message"`
			ExecutionPayload *bellatrixSpec.ExecutionPayload `json:"execution_payload"`
			Signature        phase0.BLSSignature             `json:"signature"`
			Proofs           *InclusionProof                 `json:"proofs"`
		}{
			Message:          v.Bellatrix.Message,
			ExecutionPayload: v.Bellatrix.ExecutionPayload,
			Signature:        v.Bellatrix.Signature,
			Proofs:           v.Proofs,
		})
	case consensusSpec.DataVersionCapella:
		return json.Marshal(struct {
			Message          *v1.BidTrace                  `json:"message"`
			ExecutionPayload *capellaSpec.ExecutionPayload `json:"execution_payload"`
			Signature        phase0.BLSSignature           `json:"signature"`
			Proofs           *InclusionProof               `json:"proofs"`
		}{
			Message:          v.Capella.Message,
			ExecutionPayload: v.Capella.ExecutionPayload,
			Signature:        v.Capella.Signature,
			Proofs:           v.Proofs,
		})
	case consensusSpec.DataVersionDeneb:
		return json.Marshal(struct {
			Message          *v1.BidTrace                `json:"message"`
			ExecutionPayload *denebSpec.ExecutionPayload `json:"execution_payload"`
			Signature        phase0.BLSSignature         `json:"signature"`
			Proofs           *InclusionProof             `json:"proofs"`
			BlobsBundle      *deneb.BlobsBundle          `json:"blobs_bundle"`
		}{
			Message:          v.Deneb.Message,
			ExecutionPayload: v.Deneb.ExecutionPayload,
			Signature:        v.Deneb.Signature,
			BlobsBundle:      v.Deneb.BlobsBundle,
			Proofs:           v.Proofs,
		})
	}

	return nil, fmt.Errorf("unknown data version %d", v.Version)
}

func (v *VersionedSubmitBlockRequestWithProofs) String() string {
	return common.JSONStringify(v)
}

// SignedConstraintsList are a list of proposer constraints that a builder must satisfy
// in order to produce a valid bid. This is not defined on the
// [spec](https://chainbound.github.io/bolt-docs/api/builder)
// but it's useful as an helper type
type SignedConstraintsList = []*SignedConstraints

// Reference: https://chainbound.github.io/bolt-docs/api/builder
type SignedConstraints struct {
	Message   ConstraintsMessage  `json:"message"`
	Signature phase0.BLSSignature `json:"signature"`
}

// Reference: https://chainbound.github.io/bolt-docs/api/builder
type ConstraintsMessage struct {
	Pubkey       phase0.BLSPubKey `json:"pubkey"`
	Slot         uint64           `json:"slot"`
	Top          bool             `json:"top"`
	Transactions []*Transaction   // Custom marshal and unmarshal implemented below
}

func (c *ConstraintsMessage) MarshalJSON() ([]byte, error) {
	transactionBytes := make([]common.HexBytes, len(c.Transactions))
	for i, tx := range c.Transactions {
		bytes, err := tx.MarshalBinary()
		if err != nil {
			return nil, err
		}

		transactionBytes[i] = bytes
	}

	type Alias ConstraintsMessage
	return json.Marshal(&struct {
		*Alias
		Transactions []common.HexBytes `json:"transactions"`
	}{
		Alias:        (*Alias)(c),
		Transactions: transactionBytes,
	})
}

func (c *ConstraintsMessage) UnmarshalJSON(data []byte) error {
	type Alias ConstraintsMessage
	aux := &struct {
		Transactions []common.HexBytes `json:"transactions"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	c.Transactions = make([]*Transaction, len(aux.Transactions))
	for i, txBytes := range aux.Transactions {
		tx := new(Transaction)
		if err := tx.UnmarshalBinary(txBytes); err != nil {
			return err
		}

		c.Transactions[i] = tx
	}

	return nil
}

// Digest returns the sha256 digest of the constraints message. This is what needs to be signed.
func (c *SignedConstraints) Digest() []byte {
	hasher := sha256.New()
	// NOTE: ignoring errors here
	slotBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(slotBytes, c.Message.Slot)

	var top byte
	if c.Message.Top {
		top = 1
	} else {
		top = 0
	}

	hasher.Write(c.Message.Pubkey[:])
	hasher.Write(slotBytes)
	hasher.Write([]byte{top})

	for _, tx := range c.Message.Transactions {
		hasher.Write(tx.Hash().Bytes())

	}

	return hasher.Sum(nil)
}

// VerifySignature verifies the signature of a signed constraints message. IMPORTANT: it uses the Bolt signing domain to
// verify the signature.
func (c *SignedConstraints) VerifySignature(pubkey phase0.BLSPubKey, domain phase0.Domain) (bool, error) {
	signingData := phase0.SigningData{ObjectRoot: phase0.Root(c.Digest()), Domain: domain}
	root, err := signingData.HashTreeRoot()
	if err != nil {
		return false, err
	}

	return bls.VerifySignatureBytes(root[:], c.Signature[:], pubkey[:])
}

// List of signed delegations
type SignedDelegations = []*SignedDelegation

type SignedDelegation struct {
	Message   Delegation          `json:"message"`
	Signature phase0.BLSSignature `json:"signature"`
}

type Delegation struct {
	ValidatorPubkey phase0.BLSPubKey `json:"validator_pubkey"`
	DelegateePubkey phase0.BLSPubKey `json:"delegatee_pubkey"`
}

// Digest returns the sha256 digest of the delegation. This is what needs to be signed.
func (d *SignedDelegation) Digest() []byte {
	hasher := sha256.New()
	// NOTE: ignoring errors here
	hasher.Write(d.Message.ValidatorPubkey[:])
	hasher.Write(d.Message.DelegateePubkey[:])
	return hasher.Sum(nil)
}

// VerifySignature verifies the signature of a signed delegation. IMPORTANT: it uses the Bolt signing domain to
// verify the signature.
func (d *SignedDelegation) VerifySignature(pubkey phase0.BLSPubKey, domain phase0.Domain) (bool, error) {
	signingData := phase0.SigningData{ObjectRoot: phase0.Root(d.Digest()), Domain: domain}
	root, err := signingData.HashTreeRoot()
	if err != nil {
		return false, err
	}

	return bls.VerifySignatureBytes(root[:], d.Signature[:], pubkey[:])
}
