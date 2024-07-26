package api

import (
	"errors"
	"fmt"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	gethCommon "github.com/ethereum/go-ethereum/common"
	fastSsz "github.com/ferranbt/fastssz"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/sirupsen/logrus"
)

var (
	ErrNilConstraint             = errors.New("nil constraint")
	ErrNilProof                  = errors.New("nil proof")
	ErrInvalidProofs             = errors.New("proof verification failed")
	ErrInvalidRoot               = errors.New("failed getting tx root from bid")
	ErrHashesIndexesMismatch     = errors.New("proof transaction hashes and indexes length mismatch")
	ErrHashesConstraintsMismatch = errors.New("proof transaction hashes and constraints length mismatch")
)

// verifyInclusionProof verifies the proofs against the constraints, and returns an error if the proofs are invalid.
//
// NOTE: assumes constraints transactions are already without blobs
func verifyInclusionProof(log *logrus.Entry, transactionsRoot phase0.Root, proof *common.InclusionProof, hashToConstraints HashToConstraintDecoded) error {
	if proof == nil {
		return ErrNilProof
	}

	if len(proof.TransactionHashes) != len(proof.GeneralizedIndexes) {
		return ErrHashesIndexesMismatch
	}

	if len(proof.TransactionHashes) != len(hashToConstraints) {
		return ErrHashesIndexesMismatch
	}

	leaves := make([][]byte, len(hashToConstraints))
	indexes := make([]int, len(proof.GeneralizedIndexes))

	for i, hash := range proof.TransactionHashes {
		constraint, ok := hashToConstraints[gethCommon.Hash(hash)]
		if constraint == nil || !ok {
			return ErrNilConstraint
		}

		// Compute the hash tree root for the raw preconfirmed transaction
		// and use it as "Leaf" in the proof to be verified against
		encoded, err := constraint.Tx.MarshalBinary()
		if err != nil {
			log.WithError(err).Error("error marshalling transaction without blob tx sidecar")
			return err
		}

		tx := Transaction(encoded)
		txHashTreeRoot, err := tx.HashTreeRoot()
		if err != nil {
			return ErrInvalidRoot
		}

		leaves[i] = txHashTreeRoot[:]
		indexes[i] = int(proof.GeneralizedIndexes[i])
		i++
	}

	hashes := make([][]byte, len(proof.MerkleHashes))
	for i, hash := range proof.MerkleHashes {
		hashes[i] = []byte(*hash)
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
