package api

import (
	"errors"
	"fmt"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	fastSsz "github.com/ferranbt/fastssz"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/sirupsen/logrus"
)

var (
	ErrNilProof      = errors.New("nil proof")
	ErrInvalidProofs = errors.New("proof verification failed")
	ErrInvalidRoot   = errors.New("failed getting tx root from bid")
)

// verifyConstraintProofs verifies the proofs against the constraints, and returns an error if the proofs are invalid.
func (api *RelayAPI) verifyConstraintProofs(transactionsRoot phase0.Root, proofs []*common.PreconfirmationWithProof, constraints Constraints) error {
	log := api.log.WithFields(logrus.Fields{})
	// BOLT: verify preconfirmation inclusion proofs. If they don't match, we don't consider the bid to be valid.
	if proofs != nil {
		// BOLT: remove unnecessary fields while logging
		log.WithFields(logrus.Fields{})

		log.WithField("len", len(proofs)).Info("[BOLT]: Verifying constraint proofs")

		for _, proof := range proofs {
			if proof == nil {
				log.Warn("[BOLT]: Nil proof!")
				return ErrNilProof
			}

			// Find the raw tx with the hash specified
			constraint, ok := constraints[proof.TxHash]
			if !ok {
				log.Warnf("[BOLT]: Tx hash %s not found in constraints", proof.TxHash.String())
				// We don't actually have to return an error here, the relay just provided a proof that was unnecessary
				continue
			}

			rawTx := constraint.RawTx

			if len(rawTx) == 0 {
				log.Warnf("[BOLT]: Raw tx is empty for tx hash %s", proof.TxHash.String())
				continue
			}

			// Compute the hash tree root for the raw preconfirmed transaction
			// and use it as "Leaf" in the proof to be verified against
			txHashTreeRoot, err := rawTx.HashTreeRoot()
			if err != nil {
				log.WithError(err).Error("[BOLT]: error getting tx hash tree root")
				return ErrInvalidRoot
			}

			// Verify the proof
			sszProof := proof.MerkleProof.ToFastSszProof(txHashTreeRoot[:])

			currentTime := time.Now()
			ok, err = fastSsz.VerifyProof(transactionsRoot[:], sszProof)
			elapsed := time.Since(currentTime)

			if err != nil {
				log.WithError(err).Error("error verifying merkle proof")
				return err
			}

			if !ok {
				log.Error("[BOLT]: proof verification failed: 'not ok' for tx hash: ", proof.TxHash.String())
				return ErrInvalidProofs
			} else {
				log.Info(fmt.Sprintf("[BOLT]: Preconfirmation proof verified for tx hash %s in %s", proof.TxHash.String(), elapsed))
			}
		}
	}

	return nil
}
