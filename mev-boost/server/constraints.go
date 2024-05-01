package server

import "github.com/attestantio/go-eth2-client/spec/phase0"

// Constraints is a map of constraints for a block.
type Constraints = map[phase0.Hash32]*Constraint

// Constraint is a constraint on a block. For now just preconfirmations
// or inclusion constraints.
type Constraint struct {
	RawTx Transaction `json:"rawTx"`
}

// ConstraintCache is a cache for constraints.
type ConstraintCache struct {
	// map of slots to constraints
	constraints map[uint64]Constraints
}

// NewConstraintCache creates a new constraint cache.
func NewConstraintCache() *ConstraintCache {
	return &ConstraintCache{
		// TODO: there should be a maximum length here that we can pre-allocate (probably the lookahead window size)
		constraints: make(map[uint64]Constraints),
	}
}

// AddInclusionConstraint adds an inclusion constraint to the cache at the given slot for the given transaction.
func (c *ConstraintCache) AddInclusionConstraint(slot uint64, txHash phase0.Hash32, rawTx Transaction) {
	if _, exists := c.constraints[slot]; !exists {
		c.constraints[slot] = make(map[phase0.Hash32]*Constraint)
	}

	c.constraints[slot][txHash] = &Constraint{
		RawTx: rawTx,
	}
}

// Get gets the constraints at the given slot.
func (c *ConstraintCache) Get(slot uint64) Constraints {
	return c.constraints[slot]
}

// Delete deletes the constraints at the given slot.
func (c *ConstraintCache) Delete(slot uint64) {
	delete(c.constraints, slot)
}
