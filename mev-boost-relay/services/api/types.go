package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	gethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	boostTypes "github.com/flashbots/go-boost-utils/types"
)

var (
	ErrMissingRequest   = errors.New("req is nil")
	ErrMissingSecretKey = errors.New("secret key is nil")
	ErrEmptyPayload     = errors.New("nil payload")

	NilResponse = struct{}{}
	ZeroU256    = boostTypes.IntToU256(0)
)

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type HTTPMessageResp struct {
	Message string `json:"message"`
}

type ConstraintSubscriptionAuth struct {
	PublicKey phase0.BLSPubKey `json:"publicKey"`
	Slot      uint64           `json:"slot"`
}

func (c *ConstraintSubscriptionAuth) String() string {
	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Sprintf("failed to marshal ConstraintSubscriptionAuth: %v", err)
	}
	return string(buf)
}

type (
	HashToConstraintDecoded = map[gethCommon.Hash]*ConstraintDecoded
	ConstraintDecoded       struct {
		Index *Index
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
