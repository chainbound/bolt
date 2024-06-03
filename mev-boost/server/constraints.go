package server

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
	constraints map[uint64][]*Constraint
}

// NewConstraintCache creates a new constraint cache.
// cap is the maximum number of slots to store constraints for.
func NewConstraintCache() *ConstraintCache {
	return &ConstraintCache{
		// TODO: there should be a maximum length here that we can pre-allocate (probably the lookahead window size)
		constraints: make(map[uint64][]*Constraint),
	}
}

// AddInclusionConstraint adds an inclusion constraint to the cache at the given slot for the given transaction.
func (c *ConstraintCache) AddInclusionConstraint(slot uint64, tx Transaction, index *uint64) {
	if _, exists := c.constraints[slot]; !exists {
		c.constraints[slot] = make([]*Constraint, 0)
	}

	c.constraints[slot] = append(c.constraints[slot], &Constraint{
		Tx:    tx,
		Index: index,
	})
}

// AddInclusionConstraints adds multiple inclusion constraints to the cache at the given slot
func (c *ConstraintCache) AddInclusionConstraints(slot uint64, constraints []*Constraint) {
	if _, exists := c.constraints[slot]; !exists {
		c.constraints[slot] = make([]*Constraint, 0)
	}

	c.constraints[slot] = append(c.constraints[slot], constraints...)
}

// Get gets the constraints at the given slot.
func (c *ConstraintCache) Get(slot uint64) []*Constraint {
	return c.constraints[slot]
}

// FindTransactionByHash finds the constraint for the given transaction hash and returns it.
func (c *ConstraintCache) FindTransactionByHash(txHash [32]byte) (*Constraint, bool) {
	for _, constraints := range c.constraints {
		for _, constraint := range constraints {
			hash, err := constraint.Tx.Hash()
			if err != nil {
				continue
			}

			if hash == txHash {
				return constraint, true
			}
		}
	}
	return nil, false
}

// Delete deletes the constraints at the given slot.
func (c *ConstraintCache) Delete(slot uint64) {
	delete(c.constraints, slot)
}
