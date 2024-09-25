package types

import (
	"sort"

	"github.com/ethereum/go-ethereum/common"
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
