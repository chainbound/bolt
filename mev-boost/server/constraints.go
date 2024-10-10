package server

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
	gethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	lru "github.com/hashicorp/golang-lru/v2"
)

type (
	BatchedSignedConstraints = []*SignedConstraints
	HashToTransactionDecoded = map[gethCommon.Hash]*types.Transaction
)

// SignedConstraints represents the signed constraints.
// Reference: https://docs.boltprotocol.xyz/api/builder
type SignedConstraints struct {
	Message   ConstraintsMessage  `json:"message"`
	Signature phase0.BLSSignature `json:"signature"`
}

// ConstraintsMessage represents the constraints message.
// Reference: https://docs.boltprotocol.xyz/api/builder
type ConstraintsMessage struct {
	Pubkey       phase0.BLSPubKey `json:"pubkey"`
	Slot         uint64           `json:"slot"`
	Top          bool             `json:"top"`
	Transactions []Transaction    `json:"transactions"`
}

func (s *SignedConstraints) String() string {
	return JSONStringify(s)
}

func (m *ConstraintsMessage) String() string {
	return JSONStringify(m)
}

// ConstraintsCache is a cache for constraints.
type ConstraintsCache struct {
	// map of slots to all constraints for that slot
	constraints *lru.Cache[uint64, map[gethCommon.Hash]*Transaction]
}

// NewConstraintsCache creates a new constraint cache.
// cap is the maximum number of slots to store constraints for.
func NewConstraintsCache(cap int) *ConstraintsCache {
	constraints, _ := lru.New[uint64, map[gethCommon.Hash]*Transaction](cap)
	return &ConstraintsCache{
		constraints: constraints,
	}
}

// AddInclusionConstraint adds an inclusion constraint to the cache at the given slot for the given transaction.
func (c *ConstraintsCache) AddInclusionConstraint(slot uint64, tx Transaction, index *uint64) error {
	if _, exists := c.constraints.Get(slot); !exists {
		c.constraints.Add(slot, make(map[gethCommon.Hash]*Transaction))
	}

	// parse transaction to get its hash and store it in the cache
	// for constant time lookup later
	parsedTx := new(types.Transaction)
	err := parsedTx.UnmarshalBinary(tx)
	if err != nil {
		return err
	}

	m, _ := c.constraints.Get(slot)
	m[parsedTx.Hash()] = &tx

	return nil
}

// AddInclusionConstraints adds multiple inclusion constraints to the cache at the given slot
func (c *ConstraintsCache) AddInclusionConstraints(slot uint64, transactions []Transaction) error {
	if _, exists := c.constraints.Get(slot); !exists {
		c.constraints.Add(slot, make(map[gethCommon.Hash]*Transaction))
	}

	m, _ := c.constraints.Get(slot)
	for _, tx := range transactions {
		parsedTx := new(types.Transaction)
		err := parsedTx.UnmarshalBinary(tx)
		if err != nil {
			return err
		}
		m[parsedTx.Hash()] = &tx
	}

	return nil
}

// Get gets the constraints at the given slot.
func (c *ConstraintsCache) Get(slot uint64) (map[gethCommon.Hash]*Transaction, bool) {
	return c.constraints.Get(slot)
}

// FindTransactionByHash finds the constraint for the given transaction hash and returns it.
func (c *ConstraintsCache) FindTransactionByHash(txHash gethCommon.Hash) (*Transaction, bool) {
	for _, hashToTx := range c.constraints.Values() {
		if tx, exists := hashToTx[txHash]; exists {
			return tx, true
		}
	}
	return nil, false
}

// Ref: https://docs.boltprotocol.xyz/api/builder#delegate
type SignedDelegation struct {
	Message   Delegation          `json:"message"`
	Signature phase0.BLSSignature `json:"signature"`
}

// Ref: https://docs.boltprotocol.xyz/api/builder#delegate
type Delegation struct {
	ValidatorPubkey phase0.BLSPubKey `json:"validator_pubkey"`
	DelegateePubkey phase0.BLSPubKey `json:"delegatee_pubkey"`
}

// Ref: https://docs.boltprotocol.xyz/api/builder#revoke
type SignedRevocation struct {
	Message   Revocation          `json:"message"`
	Signature phase0.BLSSignature `json:"signature"`
}

// Ref: https://docs.boltprotocol.xyz/api/builder#revoke
type Revocation struct {
	ValidatorPubkey phase0.BLSPubKey `json:"validator_pubkey"`
	DelegateePubkey phase0.BLSPubKey `json:"delegatee_pubkey"`
}
