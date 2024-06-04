package server

import (
	"github.com/chainbound/shardmap"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type BatchedSignedConstraints = []*SignedConstraints

type SignedConstraints struct {
	Message   ConstraintsMessage `json:"message"`
	Signature HexBytes           `json:"signature"`
}

type ConstraintsMessage struct {
	ValidatorIndex uint64
	Slot           uint64
	Constraints    []*Constraint
}

type Constraint struct {
	Tx    Transaction
	Index *uint64
}

// ConstraintCache is a cache for constraints.
type ConstraintCache struct {
	// map of slots to all constraints for that slot
	constraints shardmap.FIFOMap[uint64, map[common.Hash]*Constraint]
}

// NewConstraintCache creates a new constraint cache.
// cap is the maximum number of slots to store constraints for.
func NewConstraintCache(cap int) *ConstraintCache {
	return &ConstraintCache{
		constraints: *shardmap.NewFIFOMap[uint64, map[common.Hash]*Constraint](int(cap), 1, shardmap.HashUint64),
	}
}

// AddInclusionConstraint adds an inclusion constraint to the cache at the given slot for the given transaction.
func (c *ConstraintCache) AddInclusionConstraint(slot uint64, tx Transaction, index *uint64) error {
	if _, exists := c.constraints.Get(slot); !exists {
		c.constraints.Put(slot, make(map[common.Hash]*Constraint))
	}

	// parse transaction to get its hash and store it in the cache
	// for constant time lookup later
	var parsedTx = new(types.Transaction)
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
func (c *ConstraintCache) AddInclusionConstraints(slot uint64, constraints []*Constraint) error {
	if _, exists := c.constraints.Get(slot); !exists {
		c.constraints.Put(slot, make(map[common.Hash]*Constraint))
	}

	m, _ := c.constraints.Get(slot)
	for _, constraint := range constraints {
		var parsedTx = new(types.Transaction)
		err := parsedTx.UnmarshalBinary(constraint.Tx)
		if err != nil {
			return err
		}
		m[parsedTx.Hash()] = constraint
	}

	return nil
}

// Get gets the constraints at the given slot.
func (c *ConstraintCache) Get(slot uint64) (map[common.Hash]*Constraint, bool) {
	return c.constraints.Get(slot)
}

// FindTransactionByHash finds the constraint for the given transaction hash and returns it.
func (c *ConstraintCache) FindTransactionByHash(txHash common.Hash) (*Constraint, bool) {
	for kv := range c.constraints.Iter() {
		if constraint, exists := kv.Value[txHash]; exists {
			return constraint, true
		}
	}
	return nil, false
}
