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
func verifyInclusionProof(log *logrus.Entry, transactionsRoot phase0.Root, proof *common.InclusionProof, hashToConstraints HashToConstraintDecoded) error {
	if proof == nil {
		return ErrNilProof
	}

	constraints := ParseConstraintsDecoded(hashToConstraints)

	leaves := make([][]byte, len(constraints))

	for i, constraint := range constraints {
		if constraint == nil {
			return ErrNilConstraint
		}

		// Compute the hash tree root for the raw preconfirmed transaction
		// and use it as "Leaf" in the proof to be verified against
		withoutBlob, err := constraint.Tx.MarshalBinary()
		if err != nil {
			log.WithError(err).Error("error marshalling transaction without blob tx sidecar")
			return err
		}

		tx := Transaction(withoutBlob)
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
