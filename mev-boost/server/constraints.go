package server

import (
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
	constraints map[uint64]map[common.Hash]*Constraint
}

// NewConstraintCache creates a new constraint cache.
// cap is the maximum number of slots to store constraints for.
func NewConstraintCache() *ConstraintCache {
	return &ConstraintCache{
		// TODO: there should be a maximum length here that we can pre-allocate (probably the lookahead window size)
		constraints: make(map[uint64]map[common.Hash]*Constraint),
	}
}

// AddInclusionConstraint adds an inclusion constraint to the cache at the given slot for the given transaction.
func (c *ConstraintCache) AddInclusionConstraint(slot uint64, tx Transaction, index *uint64) error {
	if _, exists := c.constraints[slot]; !exists {
		c.constraints[slot] = make(map[common.Hash]*Constraint)
	}

	var parsedTx = new(types.Transaction)
	err := parsedTx.UnmarshalBinary(tx)
	if err != nil {
		return err
	}

	c.constraints[slot][parsedTx.Hash()] = &Constraint{
		Tx:    tx,
		Index: index,
	}

	return nil
}

// AddInclusionConstraints adds multiple inclusion constraints to the cache at the given slot
func (c *ConstraintCache) AddInclusionConstraints(slot uint64, constraints []*Constraint) error {
	if _, exists := c.constraints[slot]; !exists {
		c.constraints[slot] = make(map[common.Hash]*Constraint)
	}

	for _, constraint := range constraints {
		var parsedTx = new(types.Transaction)
		err := parsedTx.UnmarshalBinary(constraint.Tx)
		if err != nil {
			return err
		}
		c.constraints[slot][parsedTx.Hash()] = constraint
	}

	return nil
}

// Get gets the constraints at the given slot.
func (c *ConstraintCache) Get(slot uint64) map[common.Hash]*Constraint {
	return c.constraints[slot]
}

// FindTransactionByHash finds the constraint for the given transaction hash and returns it.
func (c *ConstraintCache) FindTransactionByHash(txHash common.Hash) (*Constraint, bool) {
	for _, constraints := range c.constraints {
		if constraint, exists := constraints[txHash]; exists {
			return constraint, true
		}
	}

	return nil, false
}

// Delete deletes the constraints at the given slot.
func (c *ConstraintCache) Delete(slot uint64) {
	delete(c.constraints, slot)
}
