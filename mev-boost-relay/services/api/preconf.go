package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/sirupsen/logrus"
)

// TODO(bolt): We should check the preconfirmation proofs in this function to discard bids that are not valid.
// This is necessary to avoid the relay accept a high bid with invalid proofs, resulting in a missed opportunity
// for the proposer, who will refuse to sign the associated block header.
//
// For the POC this is not needed
func (api *RelayAPI) handleSubmitNewBlockWithPreconfs(w http.ResponseWriter, req *http.Request) {
	var pf common.Profile
	var prevTime, nextTime time.Time

	headSlot := api.headSlot.Load()
	receivedAt := time.Now().UTC()
	prevTime = receivedAt

	args := req.URL.Query()
	isCancellationEnabled := args.Get("cancellations") == "1"

	log := api.log.WithFields(logrus.Fields{
		"method":                "submitNewBlockWithPreconfs",
		"contentLength":         req.ContentLength,
		"headSlot":              headSlot,
		"cancellationEnabled":   isCancellationEnabled,
		"timestampRequestStart": receivedAt.UnixMilli(),
	})

	// Log at start and end of request
	log.Info("request initiated")
	defer func() {
		log.WithFields(logrus.Fields{
			"timestampRequestFin": time.Now().UTC().UnixMilli(),
			"requestDurationMs":   time.Since(receivedAt).Milliseconds(),
		}).Info("request finished")
	}()

	// If cancellations are disabled but builder requested it, return error
	if isCancellationEnabled && !api.ffEnableCancellations {
		log.Info("builder submitted with cancellations enabled, but feature flag is disabled")
		api.RespondError(w, http.StatusBadRequest, "cancellations are disabled")
		return
	}

	var err error
	var reader io.Reader = req.Body
	isGzip := req.Header.Get("Content-Encoding") == "gzip"
	log = log.WithField("reqIsGzip", isGzip)
	if isGzip {
		reader, err = gzip.NewReader(req.Body)
		if err != nil {
			log.WithError(err).Warn("could not create gzip reader")
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	limitReader := io.LimitReader(reader, 10*1024*1024) // 10 MB
	requestPayloadBytes, err := io.ReadAll(limitReader)
	if err != nil {
		log.WithError(err).Warn("could not read payload")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	nextTime = time.Now().UTC()
	pf.PayloadLoad = uint64(nextTime.Sub(prevTime).Microseconds())
	prevTime = nextTime

	// BOLT: new payload type
	payload := new(common.VersionedSubmitBlockRequestWithPreconfsProofs)

	// Check for SSZ encoding
	contentType := req.Header.Get("Content-Type")
	if contentType == "application/octet-stream" {
		// TODO-BOLT: implement SSZ decoding
		panic("SSZ decoding not implemented for preconfs yet")
	} else {
		log = log.WithField("reqContentType", "json")
		if err := json.Unmarshal(requestPayloadBytes, payload); err != nil {
			api.boltLog.WithError(err).Warn("Could not decode payload - JSON")
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	num, _ := payload.Inner.BlockNumber()
	bhash, _ := payload.Inner.BlockHash()
	api.boltLog.Infof("Got decoded payload from builder: \nPayload: %v\nBlock hash: %s\nBlockNum: %d\n", payload.Inner.String(), bhash, num)
	api.boltLog.Infof("Headslot: %d\n", headSlot)

	nextTime = time.Now().UTC()
	pf.Decode = uint64(nextTime.Sub(prevTime).Microseconds())
	prevTime = nextTime

	isLargeRequest := len(requestPayloadBytes) > fastTrackPayloadSizeLimit
	// getting block submission info also validates bid trace and execution submission are not empty
	submission, err := common.GetBlockSubmissionInfo(payload.Inner)
	if err != nil {
		log.WithError(err).Warn("missing fields in submit block request")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}
	log = log.WithFields(logrus.Fields{
		"timestampAfterDecoding": time.Now().UTC().UnixMilli(),
		"slot":                   submission.BidTrace.Slot,
		"builderPubkey":          submission.BidTrace.BuilderPubkey.String(),
		"blockHash":              submission.BidTrace.BlockHash.String(),
		"proposerPubkey":         submission.BidTrace.ProposerPubkey.String(),
		"parentHash":             submission.BidTrace.ParentHash.String(),
		"value":                  submission.BidTrace.Value.Dec(),
		"numTx":                  len(submission.Transactions),
		"payloadBytes":           len(requestPayloadBytes),
		"isLargeRequest":         isLargeRequest,
	})
	// deneb specific logging
	if payload.Inner.Deneb != nil {
		log = log.WithFields(logrus.Fields{
			"numBlobs":      len(payload.Inner.Deneb.BlobsBundle.Blobs),
			"blobGasUsed":   payload.Inner.Deneb.ExecutionPayload.BlobGasUsed,
			"excessBlobGas": payload.Inner.Deneb.ExecutionPayload.ExcessBlobGas,
		})
	}

	ok := api.checkSubmissionSlotDetails(w, log, headSlot, payload.Inner, submission)
	if !ok {
		return
	}

	builderPubkey := submission.BidTrace.BuilderPubkey
	builderEntry, ok := api.checkBuilderEntry(w, log, builderPubkey)
	if !ok {
		return
	}

	log = log.WithField("builderIsHighPrio", builderEntry.status.IsHighPrio)

	gasLimit, ok := api.checkSubmissionFeeRecipient(w, log, submission.BidTrace)
	if !ok {
		return
	}

	// Don't accept blocks with 0 value
	if submission.BidTrace.Value.ToBig().Cmp(ZeroU256.BigInt()) == 0 || len(submission.Transactions) == 0 {
		log.Info("submitNewBlock failed: block with 0 value or no txs")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Sanity check the submission
	err = SanityCheckBuilderBlockSubmission(payload.Inner)
	if err != nil {
		log.WithError(err).Info("block submission sanity checks failed")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	attrs, ok := api.checkSubmissionPayloadAttrs(w, log, submission)
	if !ok {
		return
	}

	// Verify the signature
	log = log.WithField("timestampBeforeSignatureCheck", time.Now().UTC().UnixMilli())
	signature := submission.Signature
	ok, err = ssz.VerifySignature(submission.BidTrace, api.opts.EthNetDetails.DomainBuilder, builderPubkey[:], signature[:])
	log = log.WithField("timestampAfterSignatureCheck", time.Now().UTC().UnixMilli())
	if err != nil {
		log.WithError(err).Warn("failed verifying builder signature")
		api.RespondError(w, http.StatusBadRequest, "failed verifying builder signature")
		return
	} else if !ok {
		log.Warn("invalid builder signature")
		api.RespondError(w, http.StatusBadRequest, "invalid signature")
		return
	}

	log = log.WithField("timestampBeforeCheckingFloorBid", time.Now().UTC().UnixMilli())

	// Create the redis pipeline tx
	tx := api.redis.NewTxPipeline()

	// channel to send simulation result to the deferred function
	simResultC := make(chan *blockSimResult, 1)
	var eligibleAt time.Time // will be set once the bid is ready

	submission, err = common.GetBlockSubmissionInfo(payload.Inner)
	if err != nil {
		log.WithError(err).Warn("missing fields in submit block request")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	bfOpts := bidFloorOpts{
		w:                    w,
		tx:                   tx,
		log:                  log,
		cancellationsEnabled: isCancellationEnabled,
		simResultC:           simResultC,
		submission:           submission,
	}
	floorBidValue, ok := api.checkFloorBidValue(bfOpts)
	if !ok {
		return
	}

	log = log.WithField("timestampAfterCheckingFloorBid", time.Now().UTC().UnixMilli())

	// Deferred saving of the builder submission to database (whenever this function ends)
	defer func() {
		savePayloadToDatabase := !api.ffDisablePayloadDBStorage
		var simResult *blockSimResult
		select {
		case simResult = <-simResultC:
		case <-time.After(10 * time.Second):
			log.Warn("timed out waiting for simulation result")
			simResult = &blockSimResult{false, false, nil, nil}
		}

		submissionEntry, err := api.db.SaveBuilderBlockSubmission(
			payload.Inner,
			simResult.requestErr,
			simResult.validationErr,
			receivedAt,
			eligibleAt,
			simResult.wasSimulated,
			savePayloadToDatabase,
			pf,
			simResult.optimisticSubmission,
			payload.Proofs, // BOLT: add merkle proofs to the submission
		)
		if err != nil {
			log.WithError(err).WithField("payload", payload).Error("saving builder block submission to database failed")
			return
		}

		err = api.db.UpsertBlockBuilderEntryAfterSubmission(submissionEntry, simResult.validationErr != nil)
		if err != nil {
			log.WithError(err).Error("failed to upsert block-builder-entry")
		}
	}()

	// ---------------------------------
	// THE BID WILL BE SIMULATED SHORTLY
	// ---------------------------------

	log = log.WithField("timestampBeforeCheckingTopBid", time.Now().UTC().UnixMilli())

	// Get the latest top bid value from Redis
	bidIsTopBid := false
	topBidValue, err := api.redis.GetTopBidValue(context.Background(), tx, submission.BidTrace.Slot, submission.BidTrace.ParentHash.String(), submission.BidTrace.ProposerPubkey.String())
	if err != nil {
		log.WithError(err).Error("failed to get top bid value from redis")
	} else {
		bidIsTopBid = submission.BidTrace.Value.ToBig().Cmp(topBidValue) == 1
		log = log.WithFields(logrus.Fields{
			"topBidValue":    topBidValue.String(),
			"newBidIsTopBid": bidIsTopBid,
		})
	}

	log = log.WithField("timestampAfterCheckingTopBid", time.Now().UTC().UnixMilli())

	nextTime = time.Now().UTC()
	pf.Prechecks = uint64(nextTime.Sub(prevTime).Microseconds())
	prevTime = nextTime

	// Simulate the block submission and save to db
	fastTrackValidation := builderEntry.status.IsHighPrio && bidIsTopBid && !isLargeRequest
	timeBeforeValidation := time.Now().UTC()

	log = log.WithFields(logrus.Fields{
		"timestampBeforeValidation": timeBeforeValidation.UTC().UnixMilli(),
		"fastTrackValidation":       fastTrackValidation,
	})

	// Construct simulation request
	opts := blockSimOptions{
		isHighPrio: builderEntry.status.IsHighPrio,
		fastTrack:  fastTrackValidation,
		log:        log,
		builder:    builderEntry,
		req: &common.BuilderBlockValidationRequest{
			VersionedSubmitBlockRequest: payload.Inner,
			RegisteredGasLimit:          gasLimit,
			ParentBeaconBlockRoot:       attrs.parentBeaconRoot,
		},
	}
	// With sufficient collateral, process the block optimistically.
	if builderEntry.status.IsOptimistic &&
		builderEntry.collateral.Cmp(submission.BidTrace.Value.ToBig()) >= 0 &&
		submission.BidTrace.Slot == api.optimisticSlot.Load() {
		go api.processOptimisticBlock(opts, simResultC)
	} else {
		// Simulate block (synchronously).
		requestErr, validationErr := api.simulateBlock(context.Background(), opts) // success/error logging happens inside
		simResultC <- &blockSimResult{requestErr == nil, false, requestErr, validationErr}
		validationDurationMs := time.Since(timeBeforeValidation).Milliseconds()
		log = log.WithFields(logrus.Fields{
			"timestampAfterValidation": time.Now().UTC().UnixMilli(),
			"validationDurationMs":     validationDurationMs,
		})
		if requestErr != nil { // Request error
			if os.IsTimeout(requestErr) {
				api.RespondError(w, http.StatusGatewayTimeout, "validation request timeout")
			} else {
				api.RespondError(w, http.StatusBadRequest, requestErr.Error())
			}
			return
		} else {
			if validationErr != nil {
				api.RespondError(w, http.StatusBadRequest, validationErr.Error())
				return
			}
		}
	}

	nextTime = time.Now().UTC()
	pf.Simulation = uint64(nextTime.Sub(prevTime).Microseconds())
	prevTime = nextTime

	// If cancellations are enabled, then abort now if this submission is not the latest one
	if isCancellationEnabled {
		// Ensure this request is still the latest one. This logic intentionally ignores the value of the bids and makes the current active bid the one
		// that arrived at the relay last. This allows for builders to reduce the value of their bid (effectively cancel a high bid) by ensuring a lower
		// bid arrives later. Even if the higher bid takes longer to simulate, by checking the receivedAt timestamp, this logic ensures that the low bid
		// is not overwritten by the high bid.
		//
		// NOTE: this can lead to a rather tricky race condition. If a builder submits two blocks to the relay concurrently, then the randomness of network
		// latency will make it impossible to predict which arrives first. Thus a high bid could unintentionally be overwritten by a low bid that happened
		// to arrive a few microseconds later. If builders are submitting blocks at a frequency where they cannot reliably predict which bid will arrive at
		// the relay first, they should instead use multiple pubkeys to avoid uninitentionally overwriting their own bids.
		latestPayloadReceivedAt, err := api.redis.GetBuilderLatestPayloadReceivedAt(context.Background(), tx, submission.BidTrace.Slot, submission.BidTrace.BuilderPubkey.String(), submission.BidTrace.ParentHash.String(), submission.BidTrace.ProposerPubkey.String())
		if err != nil {
			log.WithError(err).Error("failed getting latest payload receivedAt from redis")
		} else if receivedAt.UnixMilli() < latestPayloadReceivedAt {
			log.Infof("already have a newer payload: now=%d / prev=%d", receivedAt.UnixMilli(), latestPayloadReceivedAt)
			api.RespondError(w, http.StatusBadRequest, "already using a newer payload")
			return
		}
	}
	redisOpts := redisUpdateBidOpts{
		w:                    w,
		tx:                   tx,
		log:                  log,
		cancellationsEnabled: isCancellationEnabled,
		receivedAt:           receivedAt,
		floorBidValue:        floorBidValue,
		payload:              payload.Inner,
	}
	updateBidResult, getPayloadResponse, ok := api.updateRedisBid(redisOpts, payload.Proofs)
	if !ok {
		return
	}

	// Add fields to logs
	log = log.WithFields(logrus.Fields{
		"timestampAfterBidUpdate":    time.Now().UTC().UnixMilli(),
		"wasBidSavedInRedis":         updateBidResult.WasBidSaved,
		"wasTopBidUpdated":           updateBidResult.WasTopBidUpdated,
		"topBidValue":                updateBidResult.TopBidValue,
		"prevTopBidValue":            updateBidResult.PrevTopBidValue,
		"profileRedisSavePayloadUs":  updateBidResult.TimeSavePayload.Microseconds(),
		"profileRedisUpdateTopBidUs": updateBidResult.TimeUpdateTopBid.Microseconds(),
		"profileRedisUpdateFloorUs":  updateBidResult.TimeUpdateFloor.Microseconds(),
	})

	if updateBidResult.WasBidSaved {
		// Bid is eligible to win the auction
		eligibleAt = time.Now().UTC()
		log = log.WithField("timestampEligibleAt", eligibleAt.UnixMilli())

		// Save to memcache in the background
		if api.memcached != nil {
			go func() {
				err = api.memcached.SaveExecutionPayload(submission.BidTrace.Slot, submission.BidTrace.ProposerPubkey.String(), submission.BidTrace.BlockHash.String(), getPayloadResponse)
				if err != nil {
					log.WithError(err).Error("failed saving execution payload in memcached")
				}
			}()
		}
	}

	nextTime = time.Now().UTC()
	pf.RedisUpdate = uint64(nextTime.Sub(prevTime).Microseconds())
	pf.Total = uint64(nextTime.Sub(receivedAt).Microseconds())

	// All done, log with profiling information
	log.WithFields(logrus.Fields{
		"profileDecodeUs":    pf.Decode,
		"profilePrechecksUs": pf.Prechecks,
		"profileSimUs":       pf.Simulation,
		"profileRedisUs":     pf.RedisUpdate,
		"profileTotalUs":     pf.Total,
	}).Info("received block from builder")
	w.WriteHeader(http.StatusOK)
}
