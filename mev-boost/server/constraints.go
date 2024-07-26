package server

import (
	"slices"
	"sort"

	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	gethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	lru "github.com/hashicorp/golang-lru/v2"
)

type BatchedSignedConstraints = []*SignedConstraints

type SignedConstraints struct {
	Message   ConstraintsMessage  `json:"message"`
	Signature phase0.BLSSignature `json:"signature"`
}

type ConstraintsMessage struct {
	ValidatorIndex uint64        `json:"validator_index"`
	Slot           uint64        `json:"slot"`
	Constraints    []*Constraint `json:"constraints"`
}

type Constraint struct {
	Tx    Transaction `json:"tx"`
	Index *uint64     `json:"index"`
}

func (s *SignedConstraints) String() string {
	return JSONStringify(s)
}

func (m *ConstraintsMessage) String() string {
	return JSONStringify(m)
}

func (c *Constraint) String() string {
	return JSONStringify(c)
}

// ConstraintCache is a cache for constraints.
type ConstraintCache struct {
	// map of slots to all constraints for that slot
	constraints *lru.Cache[uint64, map[gethCommon.Hash]*Constraint]
}

// NewConstraintCache creates a new constraint cache.
// cap is the maximum number of slots to store constraints for.
func NewConstraintCache(cap int) *ConstraintCache {
	constraints, _ := lru.New[uint64, map[gethCommon.Hash]*Constraint](cap)
	return &ConstraintCache{
		constraints: constraints,
	}
}

// AddInclusionConstraint adds an inclusion constraint to the cache at the given slot for the given transaction.
func (c *ConstraintCache) AddInclusionConstraint(slot uint64, tx Transaction, index *uint64) error {
	if _, exists := c.constraints.Get(slot); !exists {
		c.constraints.Add(slot, make(map[gethCommon.Hash]*Constraint))
	}

	// parse transaction to get its hash and store it in the cache
	// for constant time lookup later
	parsedTx := new(types.Transaction)
	err := parsedTx.UnmarshalBinary(tx)
	if err != nil {
		return err
	}

	m, _ := c.constraints.Get(slot)
	m[parsedTx.Hash()] = &Constraint{
		Tx:    tx,
		Index: index,
	}

	return nil
}

// AddInclusionConstraints adds multiple inclusion constraints to the cache at the given slot
func (c *ConstraintCache) AddInclusionConstraints(slot uint64, constraints []*Constraint, blobsBundleCache *builderApiDeneb.BlobsBundle) error {
	if _, exists := c.constraints.Get(slot); !exists {
		c.constraints.Add(slot, make(map[gethCommon.Hash]*Constraint))
	}

	m, _ := c.constraints.Get(slot)
	for _, constraint := range constraints {
		tx := new(types.Transaction)
		err := tx.UnmarshalBinary(constraint.Tx)
		if err != nil {
			return err
		}
		m[tx.Hash()] = constraint
		if sidecar := tx.BlobTxSidecar(); sidecar != nil {
			consensusBlobs := make([]deneb.Blob, 0, len(sidecar.Blobs))
			for _, blob := range sidecar.Blobs {
				consensusBlobs = append(consensusBlobs, deneb.Blob(blob))
			}
			blobsBundleCache.Blobs = append(blobsBundleCache.Blobs, consensusBlobs...)
			consensusKZGCommitments := make([]deneb.KZGCommitment, 0, len(sidecar.Commitments))
			for _, commitment := range sidecar.Commitments {
				consensusKZGCommitments = append(consensusKZGCommitments, deneb.KZGCommitment(commitment))
			}
			blobsBundleCache.Commitments = append(blobsBundleCache.Commitments, consensusKZGCommitments...)
			consensusKZGProofs := make([]deneb.KZGProof, 0, len(sidecar.Proofs))
			for _, proof := range sidecar.Proofs {
				consensusKZGProofs = append(consensusKZGProofs, deneb.KZGProof(proof))
			}
			blobsBundleCache.Proofs = append(blobsBundleCache.Proofs, consensusKZGProofs...)
		}
	}

	return nil
}

// Get gets the constraints at the given slot.
func (c *ConstraintCache) Get(slot uint64) (map[gethCommon.Hash]*Constraint, bool) {
	return c.constraints.Get(slot)
}

// FindTransactionByHash finds the constraint for the given transaction hash and returns it.
func (c *ConstraintCache) FindTransactionByHash(txHash gethCommon.Hash) (*Constraint, bool) {
	for _, hashToConstraint := range c.constraints.Values() {
		if constraint, exists := hashToConstraint[txHash]; exists {
			return constraint, true
		}
	}
	return nil, false
}

type (
	HashToConstraintDecoded = map[gethCommon.Hash]*ConstraintDecoded
	ConstraintDecoded       struct {
		Index *uint64
		Tx    *types.Transaction
	}
)

// ParseConstraintsDecoded receives a map of constraints and
// - creates a slice of constraints sorted by index
// - creates a slice of constraints without index sorted by nonce and hash
// Returns the concatenation of the slices
func ParseConstraintsDecoded(constraints HashToConstraintDecoded) []*ConstraintDecoded {
	// Here we initialize and track the constraints left to be executed along
	// with their gas requirements
	constraintsOrderedByIndex := make([]*ConstraintDecoded, 0, len(constraints))
	constraintsWithoutIndex := make([]*ConstraintDecoded, 0, len(constraints))

	for _, constraint := range constraints {
		if constraint.Index == nil {
			constraintsWithoutIndex = append(constraintsWithoutIndex, constraint)
		} else {
			constraintsOrderedByIndex = append(constraintsOrderedByIndex, constraint)
		}
	}

	// Sorts the constraints by index ascending
	sort.Slice(constraintsOrderedByIndex, func(i, j int) bool {
		// By assumption, all constraints here have a non-nil index
		return *constraintsOrderedByIndex[i].Index < *constraintsOrderedByIndex[j].Index
	})

	// Sorts the unindexed constraints by nonce ascending and by hash
	sort.Slice(constraintsWithoutIndex, func(i, j int) bool {
		iNonce := constraintsWithoutIndex[i].Tx.Nonce()
		jNonce := constraintsWithoutIndex[j].Tx.Nonce()
		// Sort by hash
		if iNonce == jNonce {
			return constraintsWithoutIndex[i].Tx.Hash().Cmp(constraintsWithoutIndex[j].Tx.Hash()) < 0
		}
		return iNonce < jNonce
	})

	constraintsConcat := slices.Concat(constraintsOrderedByIndex, constraintsWithoutIndex)

	return constraintsConcat
}
