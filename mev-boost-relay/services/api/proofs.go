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
	ErrNilConstraint = errors.New("nil constraint")
	ErrNilProof      = errors.New("nil proof")
	ErrInvalidProofs = errors.New("proof verification failed")
	ErrInvalidRoot   = errors.New("failed getting tx root from bid")
)

// verifyConstraintProofs verifies the proofs against the constraints, and returns an error if the proofs are invalid.
func verifyConstraintProofs(log *logrus.Entry, transactionsRoot phase0.Root, proofs []*common.PreconfirmationWithProof, constraints map[phase0.Hash32]*Constraint) error {
	if proofs == nil {
		return errors.New("proofs are nil")
	}

	log.WithField("len", len(proofs)).Info("[BOLT]: Verifying constraint proofs")

	for hash, constraint := range constraints {
		if constraint == nil {
			log.Warn("[BOLT]: nil constraint!")
			return ErrNilConstraint
		}

		if len(constraint.Tx) == 0 {
			log.Warnf("[BOLT]: Raw tx is empty for constraint tx hash %s", hash)
			continue
		}

		// Compute the hash tree root for the raw preconfirmed transaction
		// and use it as "Leaf" in the proof to be verified against
		tx := Transaction(constraint.Tx)
		txHashTreeRoot, err := tx.HashTreeRoot()
		if err != nil {
			log.WithError(err).Error("[BOLT]: error getting tx hash tree root")
			return ErrInvalidRoot
		}

		proof := Find(proofs, func(proof *common.PreconfirmationWithProof) bool {
			return proof.TxHash == hash
		})

		if proof == nil {
			log.Warnf("[BOLT]: No proof found for tx hash %s", hash)
			return ErrNilProof
		}

		// Verify the proof
		sszProof := proof.MerkleProof.ToFastSszProof(txHashTreeRoot[:])

		currentTime := time.Now()
		ok, err := fastSsz.VerifyProof(transactionsRoot[:], sszProof)
		elapsed := time.Since(currentTime)

		if err != nil {
			log.WithError(err).Error("error verifying merkle proof")
			return err
		}

		if !ok {
			log.Error("[BOLT]: constraint proof verification failed: 'not ok' for tx hash: ", proof.TxHash.String())
			return ErrInvalidProofs
		} else {
			log.Info(fmt.Sprintf("[BOLT]: constraint proof verified for tx hash %s in %s", proof.TxHash.String(), elapsed))
		}
	}

	return nil
}
