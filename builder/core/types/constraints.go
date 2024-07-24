package types

import (
	"sort"

	"github.com/ethereum/go-ethereum/common"
)

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

// ParseConstraintsDecoded receives a map of constraints and returns
// - a slice of constraints sorted by index
// - a slice of constraints without index sorted by nonce and hash
// - the total gas required by the constraints
// - the total blob gas required by the constraints
func ParseConstraintsDecoded(constraints HashToConstraintDecoded) ([]*ConstraintDecoded, []*ConstraintDecoded, uint64, uint64) {
	// Here we initialize and track the constraints left to be executed along
	// with their gas requirements
	constraintsOrderedByIndex := make([]*ConstraintDecoded, 0, len(constraints))
	constraintsWithoutIndex := make([]*ConstraintDecoded, 0, len(constraints))
	constraintsTotalGasLeft := uint64(0)
	constraintsTotalBlobGasLeft := uint64(0)

	for _, constraint := range constraints {
		if constraint.Index == nil {
			constraintsWithoutIndex = append(constraintsWithoutIndex, constraint)
		} else {
			constraintsOrderedByIndex = append(constraintsOrderedByIndex, constraint)
		}
		constraintsTotalGasLeft += constraint.Tx.Gas()
		constraintsTotalBlobGasLeft += constraint.Tx.BlobGas()
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

	return constraintsOrderedByIndex, constraintsWithoutIndex, constraintsTotalGasLeft, constraintsTotalBlobGasLeft
}
