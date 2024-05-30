package types

import "github.com/ethereum/go-ethereum/common"

// NOTE: not the greatest place for this type but given that it uses
// `common.Hash`, `Transaction` and it's used in both the builder
// package and the miner package, here it's a good place for now

type (
	HashToConstraintDecoded = map[common.Hash]*ConstraintDecoded
	ConstraintDecoded       struct {
		Index *uint64
		Tx    *Transaction
	}
)
