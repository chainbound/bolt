package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

type SignedConstraintSubmission struct {
	Message   *ConstraintSubmission
	Signature phase0.BLSSignature `ssz-size:"96"`
}

type signedConstraintSubmissionJSON struct {
	Message   *ConstraintSubmission `json:"message"`
	Signature string                `json:"signature"`
}

func (s *SignedConstraintSubmission) MarshalJSON() ([]byte, error) {
	return json.Marshal(&signedConstraintSubmissionJSON{
		Message:   s.Message,
		Signature: fmt.Sprintf("%#x", s.Signature),
	})
}

func (s *SignedConstraintSubmission) UnmarshalJSON(input []byte) error {
	var data signedConstraintSubmissionJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return errors.Wrap(err, "invalid JSON")
	}

	if data.Message == nil {
		return errors.New("message missing")
	}

	s.Message = data.Message

	if data.Signature == "" {
		return errors.New("signature missing")
	}

	signature, err := hex.DecodeString(strings.TrimPrefix(data.Signature, "0x"))
	if err != nil {
		return errors.Wrap(err, "invalid signature")
	}

	if len(signature) != phase0.SignatureLength {
		return errors.New("incorrect length for signature")
	}
	copy(s.Signature[:], signature)

	return nil
}

type ConstraintSubmission struct {
	Slot   uint64
	TxHash phase0.Hash32 `ssz-size:"32"`
	RawTx  Transaction   `ssz-max:"1073741824"`
}

type constraintSubmissionJSON struct {
	Slot   uint64 `json:"slot"`
	TxHash string `json:"txHash"`
	RawTx  string `json:"rawTx"`
}

func (c *ConstraintSubmission) MarshalJSON() ([]byte, error) {
	return json.Marshal(&constraintSubmissionJSON{
		Slot:   c.Slot,
		TxHash: c.TxHash.String(),
		RawTx:  fmt.Sprintf("%#x", c.RawTx),
	})
}

func (c *ConstraintSubmission) UnmarshalJSON(input []byte) error {
	var data constraintSubmissionJSON
	if err := json.Unmarshal(input, &data); err != nil {
		return err
	}
	c.Slot = data.Slot

	txHash, err := hex.DecodeString((strings.TrimPrefix(data.TxHash, "0x")))
	if err != nil {
		return errors.Wrap(err, "invalid tx hash")
	}

	copy(c.TxHash[:], txHash)

	rawTx, err := hex.DecodeString((strings.TrimPrefix(data.RawTx, "0x")))
	if err != nil {
		return errors.Wrap(err, "invalid raw tx")
	}

	copy(c.RawTx[:], rawTx)

	return nil
}

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
