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

// verifyInclusionProof verifies the proofs against the constraints, and returns an error if the proofs are invalid.
func verifyInclusionProof(log *logrus.Entry, transactionsRoot phase0.Root, proof *common.InclusionProof, constraints map[phase0.Hash32]*Constraint) error {
	if proof == nil {
		return ErrNilProof
	}

	leaves := make([][]byte, len(constraints))

	i := 0
	for hash, constraint := range constraints {
		if constraint == nil {
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
			return ErrInvalidRoot
		}

		leaves[i] = txHashTreeRoot[:]
		i++
	}

	hashes := make([][]byte, len(proof.MerkleHashes))
	for i, hash := range proof.MerkleHashes {
		hashes[i] = []byte(*hash)
	}
	indexes := make([]int, len(proof.GeneralizedIndexes))
	for i, index := range proof.GeneralizedIndexes {
		indexes[i] = int(index)
	}

	currentTime := time.Now()
	ok, err := fastSsz.VerifyMultiproof(transactionsRoot[:], hashes, leaves, indexes)
	elapsed := time.Since(currentTime)
	if err != nil {
		log.WithError(err).Error("error verifying merkle proof")
		return err
	}

	if !ok {
		return ErrInvalidProofs
	} else {
		log.Info(fmt.Sprintf("[BOLT]: inclusion proof verified in %s", elapsed))
	}

	return nil
}
