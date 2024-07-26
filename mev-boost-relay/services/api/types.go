package api

import (
	"encoding/json"
	"errors"
	"fmt"

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
