package api

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/mev-boost-relay/common"
)

// These types are taken from https://github.com/chainbound/bolt/pull/11/files#diff-0fa8405accc1cdc5b108ba0210a8f1d99e25e1a5173e45e1516d73c294b061c4

type ConstraintStream struct {
	Message   *ConstraintStream   `json:"message"`
	Signature phase0.BLSSignature `json:"signature"`
}

type ConstraintStreamMessage struct {
	ValidatorIndex uint64              `json:"validator_index"`
	Slot           uint64              `json:"slot"`
	Constraints    []*ConstraintSchema `json:"constraints"`
}

type ConstraintSchema struct {
	Tx    common.HexBytes `json:"tx"`
	Index *uint64         `json:"index"`
}

func (c *ConstraintStream) String() string {
	return JSONStringify(c)
}

func (c *ConstraintStreamMessage) String() string {
	return JSONStringify(c)
}

func (c *ConstraintSchema) String() string {
	return JSONStringify(c)
}

// ConstraintsMap is a map of constraints for a block.
type ConstraintsMap = map[phase0.Hash32]*ConstraintSchema

// ConstraintCache is a cache for constraints.
type ConstraintCache struct {
	// map of slots to constraints
	constraints map[uint64]ConstraintsMap
}
