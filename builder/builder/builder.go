package builder

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	_ "os"
	"slices"
	"strings"
	"sync"
	"time"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiBellatrix "github.com/attestantio/go-builder-client/api/bellatrix"
	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	utilbellatrix "github.com/attestantio/go-eth2-client/util/bellatrix"
	"github.com/chainbound/shardmap"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	blockvalidation "github.com/ethereum/go-ethereum/eth/block-validation"
	"github.com/ethereum/go-ethereum/flashbotsextra"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/holiman/uint256"
	"golang.org/x/time/rate"

	"github.com/cenkalti/backoff/v4"
)

const (
	RateLimitIntervalDefault     = 500 * time.Millisecond
	RateLimitBurstDefault        = 10
	BlockResubmitIntervalDefault = 500 * time.Millisecond

	SubmissionOffsetFromEndOfSlotSecondsDefault = 3 * time.Second
)

const (
	SubscribeConstraintsPath = "/relay/v1/builder/constraints"
)

type PubkeyHex string

type ValidatorData struct {
	Pubkey       PubkeyHex
	FeeRecipient bellatrix.ExecutionAddress
	GasLimit     uint64
}

type IRelay interface {
	SubmitBlock(msg *builderSpec.VersionedSubmitBlockRequest, vd ValidatorData) error
	SubmitBlockWithProofs(msg *common.VersionedSubmitBlockRequestWithProofs, vd ValidatorData) error
	GetValidatorForSlot(nextSlot uint64) (ValidatorData, error)
	Config() RelayConfig
	Start() error
	Stop()
}

type IBuilder interface {
	OnPayloadAttribute(attrs *types.BuilderPayloadAttributes) error
	Start() error
	Stop() error
}

type Builder struct {
	ds                          flashbotsextra.IDatabaseService
	blockConsumer               flashbotsextra.BlockConsumer
	relay                       IRelay
	eth                         IEthereumService
	dryRun                      bool
	ignoreLatePayloadAttributes bool
	validator                   *blockvalidation.BlockValidationAPI
	beaconClient                IBeaconClient
	builderSecretKey            *bls.SecretKey
	builderPublicKey            phase0.BLSPubKey
	builderSigningDomain        phase0.Domain
	builderResubmitInterval     time.Duration
	discardRevertibleTxOnErr    bool

	// constraintsCache is a map from slot to the constraints made by proposers
	constraintsCache *shardmap.FIFOMap[uint64, common.SignedConstraintsList]

	limiter                       *rate.Limiter
	submissionOffsetFromEndOfSlot time.Duration

	slotMu        sync.Mutex
	slotAttrs     types.BuilderPayloadAttributes
	slotCtx       context.Context
	slotCtxCancel context.CancelFunc

	stop chan struct{}
}

// BuilderArgs is a struct that contains all the arguments needed to create a new Builder
type BuilderArgs struct {
	boltCCEndpoint                string
	sk                            *bls.SecretKey
	ds                            flashbotsextra.IDatabaseService
	blockConsumer                 flashbotsextra.BlockConsumer
	relay                         IRelay
	builderSigningDomain          phase0.Domain
	builderBlockResubmitInterval  time.Duration
	discardRevertibleTxOnErr      bool
	eth                           IEthereumService
	dryRun                        bool
	ignoreLatePayloadAttributes   bool
	validator                     *blockvalidation.BlockValidationAPI
	beaconClient                  IBeaconClient
	submissionOffsetFromEndOfSlot time.Duration

	limiter *rate.Limiter
}

// SubmitBlockOpts is a struct that contains all the arguments needed to submit a block to the relay
type SubmitBlockOpts struct {
	// Block is the block to submit
	Block *types.Block
	// BlockValue is the block value
	BlockValue *big.Int
	// BlobSidecars are the blob sidecars
	BlobSidecars []*types.BlobTxSidecar
	// OrdersClosedAt is the time at which orders were closed
	OrdersClosedAt time.Time
	// SealedAt is the time at which the block was sealed
	SealedAt time.Time
	// CommitedBundles are the bundles that were committed
	CommitedBundles []types.SimulatedBundle
	// AllBundles are all the bundles that were simulated
	AllBundles []types.SimulatedBundle
	// UsedSbundles are the share bundles that were used
	UsedSbundles []types.UsedSBundle
	// ProposerPubkey is the proposer's pubkey
	ProposerPubkey phase0.BLSPubKey
	// ValidatorData is the information about the validator
	ValidatorData ValidatorData
	// PayloadAttributes are the payload attributes used for block building
	PayloadAttributes *types.BuilderPayloadAttributes
}

func NewBuilder(args BuilderArgs) (*Builder, error) {
	blsPk, err := bls.PublicKeyFromSecretKey(args.sk)
	if err != nil {
		return nil, err
	}
	pk, err := utils.BlsPublicKeyToPublicKey(blsPk)
	if err != nil {
		return nil, err
	}

	if args.limiter == nil {
		args.limiter = rate.NewLimiter(rate.Every(RateLimitIntervalDefault), RateLimitBurstDefault)
	}

	if args.builderBlockResubmitInterval == 0 {
		args.builderBlockResubmitInterval = BlockResubmitIntervalDefault
	}

	if args.submissionOffsetFromEndOfSlot == 0 {
		args.submissionOffsetFromEndOfSlot = SubmissionOffsetFromEndOfSlotSecondsDefault
	}

	slotCtx, slotCtxCancel := context.WithCancel(context.Background())
	return &Builder{
		ds:                            args.ds,
		blockConsumer:                 args.blockConsumer,
		relay:                         args.relay,
		eth:                           args.eth,
		dryRun:                        args.dryRun,
		ignoreLatePayloadAttributes:   args.ignoreLatePayloadAttributes,
		validator:                     args.validator,
		beaconClient:                  args.beaconClient,
		builderSecretKey:              args.sk,
		builderPublicKey:              pk,
		builderSigningDomain:          args.builderSigningDomain,
		builderResubmitInterval:       args.builderBlockResubmitInterval,
		discardRevertibleTxOnErr:      args.discardRevertibleTxOnErr,
		submissionOffsetFromEndOfSlot: args.submissionOffsetFromEndOfSlot,

		constraintsCache: shardmap.NewFIFOMap[uint64, common.SignedConstraintsList](64, 16, shardmap.HashUint64),

		limiter:       args.limiter,
		slotCtx:       slotCtx,
		slotCtxCancel: slotCtxCancel,

		stop: make(chan struct{}, 1),
	}, nil
}

func (b *Builder) Start() error {
	// Start regular payload attributes updates
	go func() {
		c := make(chan types.BuilderPayloadAttributes)
		go b.beaconClient.SubscribeToPayloadAttributesEvents(c)

		currentSlot := uint64(0)

		for {
			select {
			case <-b.stop:
				return
			case payloadAttributes := <-c:
				// Right now we are building only on a single head. This might change in the future!
				if payloadAttributes.Slot < currentSlot {
					continue
				} else if payloadAttributes.Slot == currentSlot {
					// Subsequent sse events should only be canonical!
					if !b.ignoreLatePayloadAttributes {
						err := b.OnPayloadAttribute(&payloadAttributes)
						if err != nil {
							log.Error("error with builder processing on payload attribute",
								"latestSlot", currentSlot,
								"processedSlot", payloadAttributes.Slot,
								"headHash", payloadAttributes.HeadHash.String(),
								"error", err)
						}
					}
				} else if payloadAttributes.Slot > currentSlot {
					currentSlot = payloadAttributes.Slot
					err := b.OnPayloadAttribute(&payloadAttributes)
					if err != nil {
						log.Error("error with builder processing on payload attribute",
							"latestSlot", currentSlot,
							"processedSlot", payloadAttributes.Slot,
							"headHash", payloadAttributes.HeadHash.String(),
							"error", err)
					}
				}
			}
		}
	}()

	if err := b.relay.Start(); err != nil {
		return err
	}

	return b.SubscribeProposerConstraints()
}

// GenerateAuthenticationHeader generates an authentication string for the builder
// to subscribe to SSE constraint events emitted by relays
func (b *Builder) GenerateAuthenticationHeader() (string, error) {
	// NOTE: the `slot` acts similarly to a nonce for the message to sign, to avoid replay attacks.
	slot := b.slotAttrs.Slot
	message, err := json.Marshal(common.ConstraintSubscriptionAuth{PublicKey: b.builderPublicKey, Slot: slot})
	if err != nil {
		log.Error(fmt.Sprintf("Failed to marshal auth message: %v", err))
		return "", err
	}
	signatureEC := bls.Sign(b.builderSecretKey, message)
	subscriptionSignatureJSON := `"` + phase0.BLSSignature(bls.SignatureToBytes(signatureEC)[:]).String() + `"`
	authHeader := "BOLT " + subscriptionSignatureJSON + "," + string(message)
	return authHeader, nil
}

// SubscribeProposerConstraints subscribes to the constraints made by Bolt proposers
// which the builder pulls from relay(s) using SSE.
func (b *Builder) SubscribeProposerConstraints() error {
	// Create authentication signed message
	authHeader, err := b.GenerateAuthenticationHeader()
	if err != nil {
		log.Error(fmt.Sprintf("Failed to generate authentication header: %v", err))
		return err
	}

	// Check if `b.relay` is a RemoteRelayAggregator, if so we need to subscribe to
	// the constraints made available by all the relays
	relayAggregator, ok := b.relay.(*RemoteRelayAggregator)
	if ok {
		for _, relay := range relayAggregator.relays {
			go b.subscribeToRelayForConstraints(relay.Config().Endpoint, authHeader)
		}
	} else {
		go b.subscribeToRelayForConstraints(b.relay.Config().Endpoint, authHeader)
	}
	return nil
}

func (b *Builder) subscribeToRelayForConstraints(relayBaseEndpoint, authHeader string) error {
	attempts := 0
	// Max 10 minutes of retries
	maxAttempts := 60
	retryInterval := 10 * time.Second

	var resp *http.Response
	var err error

BEGIN:
	for {
		select {
		case <-b.stop:
			return nil
		default:
			if attempts >= maxAttempts {
				log.Error(fmt.Sprintf("Failed to subscribe to constraints after %d attempts", maxAttempts))
				return errors.New("failed to subscribe to constraints")
			}

			// try to subscribe to constraints by making an initial HTTP request
			req, err := http.NewRequest(http.MethodGet, relayBaseEndpoint+SubscribeConstraintsPath, nil)
			if err != nil {
				log.Error(fmt.Sprintf("Failed to create new http request: %v", err))
				return err
			}
			req.Header.Set("Accept-Encoding", "gzip")
			req.Header.Set("Authorization", authHeader)

			client := http.Client{}
			resp, err = client.Do(req)
			if err != nil {
				log.Error(fmt.Sprintf("Failed to connect to SSE server: %v", err))
				time.Sleep(retryInterval)
				attempts++
				continue
			}
			break BEGIN
		}
	}

	log.Info(fmt.Sprintf("Connected to SSE server: %s", relayBaseEndpoint))

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Error(fmt.Sprintf("Non-OK HTTP status: %s", resp.Status))
		return err
	}

	var reader io.Reader

	// Step 2: Check if the response is gzipped
	if resp.Header.Get("Content-Encoding") == "gzip" {
		// Step 3: Decompress the response body
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("error creating gzip reader: %v", err)
		}
		defer gzipReader.Close()
		reader = gzipReader
	} else {
		reader = resp.Body
	}

	bufReader := bufio.NewReader(reader)
	for {
		line, err := bufReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println("End of stream")
				break
			}
			log.Error("Error reading from response body: %v", err)
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")

		// We assume the data is the JSON representation of the constraints
		// TODO: downgrade this to debug level
		log.Info("Received new constraint: %s\n", data)
		constraintsSigned := make(common.SignedConstraintsList, 0, 8)
		if err := json.Unmarshal([]byte(data), &constraintsSigned); err != nil {
			log.Warn(fmt.Sprintf("Failed to unmarshal constraints: %v", err))
			continue
		}
		if len(constraintsSigned) == 0 {
			log.Warn("Received 0 length list of constraints")
			continue
		}

	OUTER:
		for _, constraint := range constraintsSigned {
			// For every constraint, we need to check if it has already been seen for the associated slot
			slotConstraints, _ := b.constraintsCache.Get(constraint.Message.Slot)
			if len(slotConstraints) == 0 {
				// New constraint for this slot, add it in the map and continue with the next constraint
				b.constraintsCache.Put(constraint.Message.Slot, common.SignedConstraintsList{constraint})
				continue
			}
			for _, slotConstraint := range slotConstraints {
				if slotConstraint.Signature == constraint.Signature {
					// The constraint has already been seen, we can continue with the next one
					continue OUTER
				}
			}
			// The constraint is new, we need to append it to the current list
			b.constraintsCache.Put(constraint.Message.Slot, append(slotConstraints, constraint))
		}
	}

	return nil
}

func (b *Builder) GetConstraintsForSlot(slot uint64) types.HashToConstraintDecoded {
	constraintsDecoded := make(types.HashToConstraintDecoded)
	constraintsSigned, _ := b.constraintsCache.Get(slot)

	for _, constraintSigned := range constraintsSigned {
		constraints := constraintSigned.Message.Constraints
		for _, constraint := range constraints {
			decoded := new(types.Transaction)
			if err := decoded.UnmarshalBinary(constraint.Tx); err != nil {
				log.Error("Failed to decode preconfirmation transaction RLP: ", err)
				continue
			}
			constraintsDecoded[decoded.Hash()] = &types.ConstraintDecoded{Index: constraint.Index, Tx: decoded}
		}
	}
	return constraintsDecoded
}

func (b *Builder) Stop() error {
	close(b.stop)
	return nil
}

// BOLT: modify to calculate merkle inclusion proofs for preconfirmed transactions
func (b *Builder) onSealedBlock(opts SubmitBlockOpts, constraints types.HashToConstraintDecoded) error {
	executableData := engine.BlockToExecutableData(opts.Block, opts.BlockValue, opts.BlobSidecars)
	var dataVersion spec.DataVersion
	if b.eth.Config().IsCancun(opts.Block.Number(), opts.Block.Time()) {
		dataVersion = spec.DataVersionDeneb
	} else if b.eth.Config().IsShanghai(opts.Block.Number(), opts.Block.Time()) {
		dataVersion = spec.DataVersionCapella
	} else {
		dataVersion = spec.DataVersionBellatrix
	}

	value, overflow := uint256.FromBig(opts.BlockValue)
	if overflow {
		err := fmt.Errorf("could not set block value due to value overflow")
		log.Error(err.Error())
		return err
	}

	blockBidMsg := builderApiV1.BidTrace{
		Slot:                 opts.PayloadAttributes.Slot,
		ParentHash:           phase0.Hash32(opts.Block.ParentHash()),
		BlockHash:            phase0.Hash32(opts.Block.Hash()),
		BuilderPubkey:        b.builderPublicKey,
		ProposerPubkey:       opts.ProposerPubkey,
		ProposerFeeRecipient: opts.ValidatorData.FeeRecipient,
		GasLimit:             executableData.ExecutionPayload.GasLimit,
		GasUsed:              executableData.ExecutionPayload.GasUsed,
		Value:                value,
	}

	payloadTransactions := opts.Block.Transactions()

	// BOLT: sanity check: verify that the block actually contains the preconfirmed transactions
	for hash, constraint := range constraints {
		if !slices.Contains(payloadTransactions, constraint.Tx) {
			log.Error(fmt.Sprintf("[BOLT]: Preconfirmed transaction %s not found in block %s", hash, opts.Block.Hash()))
			continue
		}
	}

	// BOLT: generate merkle tree from payload transactions (we need raw RLP bytes for this)
	rawTxs := make([]bellatrix.Transaction, len(payloadTransactions))
	for i, tx := range payloadTransactions {
		raw, err := tx.MarshalBinary()
		if err != nil {
			log.Error("[BOLT]: could not marshal transaction", "txHash", tx.Hash(), "err", err)
			continue
		}
		rawTxs[i] = bellatrix.Transaction(raw)
	}

	log.Info(fmt.Sprintf("[BOLT]: Generated %d raw transactions for merkle tree", len(rawTxs)))
	bellatrixPayloadTxs := utilbellatrix.ExecutionPayloadTransactions{Transactions: rawTxs}

	rootNode, err := bellatrixPayloadTxs.GetTree()
	if err != nil {
		log.Error("[BOLT]: could not get tree from transactions", "err", err)
	}

	// BOLT: Set the value of nodes. This is MANDATORY for the proof calculation
	// to output the leaf correctly. This is also never documented in fastssz. -__-
	rootNode.Hash()

	// BOLT: calculate merkle proofs for preconfirmed transactions
	preconfirmationsProofs := make([]*common.PreconfirmationWithProof, 0, len(constraints))

	timeStart := time.Now()
	for hash := range constraints {
		// get the index of the preconfirmed transaction in the block
		preconfIndex := slices.IndexFunc(payloadTransactions, func(tx *types.Transaction) bool { return tx.Hash() == hash })
		if preconfIndex == -1 {
			log.Error(fmt.Sprintf("Preconfirmed transaction %s not found in block %s", hash, opts.Block.Hash()))
			log.Error(fmt.Sprintf("block has %v transactions", len(payloadTransactions)))
			continue
		}

		// using our gen index formula: 2 * 2^20 + preconfIndex
		generalizedIndex := int(math.Pow(float64(2), float64(21))) + preconfIndex

		log.Info(fmt.Sprintf("[BOLT]: Calculating merkle proof for preconfirmed transaction %s with index %d. Preconf index: %d",
			hash, generalizedIndex, preconfIndex))

		timeStartInner := time.Now()
		proof, err := rootNode.Prove(generalizedIndex)
		if err != nil {
			log.Error("[BOLT]: could not calculate merkle proof for preconfirmed transaction", "txHash", hash, "err", err)
			continue
		}
		log.Info(fmt.Sprintf("[BOLT]: Calculated merkle proof for preconf %s in %s", hash, time.Since(timeStartInner)))
		log.Info(fmt.Sprintf("[BOLT]: LEAF: %x, Is leaf nil? %v", proof.Leaf, proof.Leaf == nil))

		merkleProof := new(common.SerializedMerkleProof)
		merkleProof.FromFastSszProof(proof)

		preconfirmationsProofs = append(preconfirmationsProofs, &common.PreconfirmationWithProof{
			TxHash:      phase0.Hash32(hash),
			MerkleProof: merkleProof,
		})

		// log.Info(fmt.Sprintf("[BOLT]: Added merkle proof for preconfirmed transaction %s", preconfirmationsProofs[i]))
	}
	timeForProofs := time.Since(timeStart)

	if len(constraints) > 0 {
		event := strings.NewReader(
			fmt.Sprintf("{ \"message\": \"BOLT-BUILDER: Created %d merkle proofs for block %d in %v\"}",
				len(constraints), opts.Block.Number(), timeForProofs))
		eventRes, err := http.Post("http://host.docker.internal:3001/events", "application/json", event)
		if err != nil {
			log.Error("Failed to log preconfirms event: ", err)
		}
		if eventRes != nil {
			defer eventRes.Body.Close()
		}
	}

	versionedBlockRequest, err := b.getBlockRequest(executableData, dataVersion, &blockBidMsg)
	if err != nil {
		log.Error("could not get block request", "err", err)
		return err
	}

	versionedBlockRequestWithPreconfsProofs := &common.VersionedSubmitBlockRequestWithProofs{
		Inner:  versionedBlockRequest,
		Proofs: preconfirmationsProofs,
	}

	if b.dryRun {
		switch dataVersion {
		case spec.DataVersionBellatrix:
			err = b.validator.ValidateBuilderSubmissionV1(&blockvalidation.BuilderBlockValidationRequest{SubmitBlockRequest: *versionedBlockRequest.Bellatrix, RegisteredGasLimit: opts.ValidatorData.GasLimit})
		case spec.DataVersionCapella:
			err = b.validator.ValidateBuilderSubmissionV2(&blockvalidation.BuilderBlockValidationRequestV2{SubmitBlockRequest: *versionedBlockRequest.Capella, RegisteredGasLimit: opts.ValidatorData.GasLimit})
		case spec.DataVersionDeneb:
			err = b.validator.ValidateBuilderSubmissionV3(&blockvalidation.BuilderBlockValidationRequestV3{SubmitBlockRequest: *versionedBlockRequest.Deneb, RegisteredGasLimit: opts.ValidatorData.GasLimit, ParentBeaconBlockRoot: *opts.Block.BeaconRoot()})
		}
		if err != nil {
			log.Error("could not validate block", "version", dataVersion.String(), "err", err)
		}
	} else {
		// NOTE: we can ignore preconfs for `processBuiltBlock`
		go b.processBuiltBlock(opts.Block, opts.BlockValue, opts.OrdersClosedAt, opts.SealedAt, opts.CommitedBundles, opts.AllBundles, opts.UsedSbundles, &blockBidMsg)
		err = b.relay.SubmitBlockWithProofs(versionedBlockRequestWithPreconfsProofs, opts.ValidatorData)
		if err != nil {
			log.Error("could not submit block", "err", err, "verion", dataVersion, "#commitedBundles", len(opts.CommitedBundles))
			return err
		}
	}

	log.Info(fmt.Sprintf("[BOLT]: Sending block to relay %s", versionedBlockRequestWithPreconfsProofs.String()))

	return nil
}

func (b *Builder) getBlockRequest(executableData *engine.ExecutionPayloadEnvelope, dataVersion spec.DataVersion, blockBidMsg *builderApiV1.BidTrace) (*builderSpec.VersionedSubmitBlockRequest, error) {
	payload, err := executableDataToExecutionPayload(executableData, dataVersion)
	if err != nil {
		log.Error("could not format execution payload", "err", err)
		return nil, err
	}

	signature, err := ssz.SignMessage(blockBidMsg, b.builderSigningDomain, b.builderSecretKey)
	if err != nil {
		log.Error("could not sign builder bid", "err", err)
		return nil, err
	}

	var versionedBlockRequest builderSpec.VersionedSubmitBlockRequest
	switch dataVersion {
	case spec.DataVersionBellatrix:
		blockSubmitReq := builderApiBellatrix.SubmitBlockRequest{
			Signature:        signature,
			Message:          blockBidMsg,
			ExecutionPayload: payload.Bellatrix,
		}
		versionedBlockRequest = builderSpec.VersionedSubmitBlockRequest{
			Version:   spec.DataVersionBellatrix,
			Bellatrix: &blockSubmitReq,
		}
	case spec.DataVersionCapella:
		blockSubmitReq := builderApiCapella.SubmitBlockRequest{
			Signature:        signature,
			Message:          blockBidMsg,
			ExecutionPayload: payload.Capella,
		}
		versionedBlockRequest = builderSpec.VersionedSubmitBlockRequest{
			Version: spec.DataVersionCapella,
			Capella: &blockSubmitReq,
		}
	case spec.DataVersionDeneb:
		blockSubmitReq := builderApiDeneb.SubmitBlockRequest{
			Signature:        signature,
			Message:          blockBidMsg,
			ExecutionPayload: payload.Deneb.ExecutionPayload,
			BlobsBundle:      payload.Deneb.BlobsBundle,
		}
		versionedBlockRequest = builderSpec.VersionedSubmitBlockRequest{
			Version: spec.DataVersionDeneb,
			Deneb:   &blockSubmitReq,
		}
	}
	return &versionedBlockRequest, err
}

func (b *Builder) processBuiltBlock(block *types.Block, blockValue *big.Int, ordersClosedAt time.Time, sealedAt time.Time, commitedBundles []types.SimulatedBundle, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle, bidTrace *builderApiV1.BidTrace) {
	back := backoff.NewExponentialBackOff()
	back.MaxInterval = 3 * time.Second
	back.MaxElapsedTime = 12 * time.Second
	err := backoff.Retry(func() error {
		return b.blockConsumer.ConsumeBuiltBlock(block, blockValue, ordersClosedAt, sealedAt, commitedBundles, allBundles, usedSbundles, bidTrace)
	}, back)
	if err != nil {
		log.Error("could not consume built block", "err", err)
	} else {
		log.Info("successfully relayed block data to consumer")
	}
}

// Called when a new payload event is received from the beacon client SSE
func (b *Builder) OnPayloadAttribute(attrs *types.BuilderPayloadAttributes) error {
	if attrs == nil {
		return nil
	}

	vd, err := b.relay.GetValidatorForSlot(attrs.Slot)
	if err != nil {
		return fmt.Errorf("could not get validator while submitting block for slot %d - %w", attrs.Slot, err)
	}

	parentBlock := b.eth.GetBlockByHash(attrs.HeadHash)
	if parentBlock == nil {
		return fmt.Errorf("parent block hash not found in block tree given head block hash %s", attrs.HeadHash)
	}

	attrs.SuggestedFeeRecipient = [20]byte(vd.FeeRecipient)
	attrs.GasLimit = core.CalcGasLimit(parentBlock.GasLimit(), vd.GasLimit)

	proposerPubkey, err := utils.HexToPubkey(string(vd.Pubkey))
	if err != nil {
		return fmt.Errorf("could not parse pubkey (%s) - %w", vd.Pubkey, err)
	}

	if !b.eth.Synced() {
		return errors.New("backend not Synced")
	}

	b.slotMu.Lock()
	defer b.slotMu.Unlock()

	if attrs.Equal(&b.slotAttrs) {
		log.Debug("ignoring known payload attribute", "slot", attrs.Slot, "hash", attrs.HeadHash)
		return nil
	}

	if b.slotCtxCancel != nil {
		b.slotCtxCancel()
	}

	slotCtx, slotCtxCancel := context.WithTimeout(context.Background(), 12*time.Second)
	b.slotAttrs = *attrs
	b.slotCtx = slotCtx
	b.slotCtxCancel = slotCtxCancel

	log.Info("[BOLT]: Inside onPayloadAttribute", "slot", attrs.Slot, "parent", attrs.HeadHash, "payloadTimestamp", uint64(attrs.Timestamp))

	go b.runBuildingJob(b.slotCtx, proposerPubkey, vd, attrs)
	return nil
}

type blockQueueEntry struct {
	block           *types.Block
	blockValue      *big.Int
	blobSidecars    []*types.BlobTxSidecar
	ordersCloseTime time.Time
	sealedAt        time.Time
	commitedBundles []types.SimulatedBundle
	allBundles      []types.SimulatedBundle
	usedSbundles    []types.UsedSBundle
}

// Continuously makes a request to the miner module with the correct params and submits the best produced block.
// on average 1 attempt per second is made.
// - Submissions to the relay are rate limited to 2 req/s
func (b *Builder) runBuildingJob(slotCtx context.Context, proposerPubkey phase0.BLSPubKey, vd ValidatorData, attrs *types.BuilderPayloadAttributes) {
	ctx, cancel := context.WithTimeout(slotCtx, 12*time.Second)
	defer cancel()

	// Submission queue for the given payload attributes
	// multiple jobs can run for different attributes fot the given slot
	// 1. When new block is ready we check if its profit is higher than profit of last best block
	//    if it is we set queueBest* to values of the new block and notify queueSignal channel.
	// 2. Submission goroutine waits for queueSignal and submits queueBest* if its more valuable than
	//    queueLastSubmittedProfit keeping queueLastSubmittedProfit to be the profit of the last submission.
	//    Submission goroutine is globally rate limited to have fixed rate of submissions for all jobs.
	var (
		queueSignal = make(chan struct{}, 1)

		queueMu                sync.Mutex
		queueLastSubmittedHash common.Hash
		queueBestEntry         blockQueueEntry
	)

	log.Debug("runBuildingJob", "slot", attrs.Slot, "parent", attrs.HeadHash, "payloadTimestamp", uint64(attrs.Timestamp))

	// fetch constraints here
	constraints := b.GetConstraintsForSlot(attrs.Slot)

	submitBestBlock := func() {
		queueMu.Lock()
		if queueBestEntry.block.Hash() != queueLastSubmittedHash {
			submitBlockOpts := SubmitBlockOpts{
				Block:             queueBestEntry.block,
				BlockValue:        queueBestEntry.blockValue,
				BlobSidecars:      queueBestEntry.blobSidecars,
				OrdersClosedAt:    queueBestEntry.ordersCloseTime,
				SealedAt:          queueBestEntry.sealedAt,
				CommitedBundles:   queueBestEntry.commitedBundles,
				AllBundles:        queueBestEntry.allBundles,
				UsedSbundles:      queueBestEntry.usedSbundles,
				ProposerPubkey:    proposerPubkey,
				ValidatorData:     vd,
				PayloadAttributes: attrs,
			}
			err := b.onSealedBlock(submitBlockOpts, constraints)

			if err != nil {
				log.Error("could not run sealed block hook", "err", err)
			} else {
				queueLastSubmittedHash = queueBestEntry.block.Hash()
			}
		}
		queueMu.Unlock()
	}

	// Avoid submitting early into a given slot. For example if slots have 12 second interval, submissions should
	// not begin until 8 seconds into the slot.
	slotTime := time.Unix(int64(attrs.Timestamp), 0).UTC()
	slotSubmitStartTime := slotTime.Add(-b.submissionOffsetFromEndOfSlot)

	// Empties queue, submits the best block for current job with rate limit (global for all jobs)
	go runResubmitLoop(ctx, b.limiter, queueSignal, submitBestBlock, slotSubmitStartTime)

	// Populates queue with submissions that increase block profit
	blockHook := func(block *types.Block, blockValue *big.Int, sidecars []*types.BlobTxSidecar, ordersCloseTime time.Time,
		committedBundles, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle,
	) {
		if ctx.Err() != nil {
			return
		}

		sealedAt := time.Now()

		queueMu.Lock()
		defer queueMu.Unlock()
		if block.Hash() != queueLastSubmittedHash {
			queueBestEntry = blockQueueEntry{
				block:           block,
				blockValue:      new(big.Int).Set(blockValue),
				blobSidecars:    sidecars,
				ordersCloseTime: ordersCloseTime,
				sealedAt:        sealedAt,
				commitedBundles: committedBundles,
				allBundles:      allBundles,
				usedSbundles:    usedSbundles,
			}

			select {
			case queueSignal <- struct{}{}:
			default:
			}
		}
	}

	// resubmits block builder requests every builderBlockResubmitInterval
	runRetryLoop(ctx, b.builderResubmitInterval, func() {
		log.Debug("retrying BuildBlock",
			"slot", attrs.Slot,
			"parent", attrs.HeadHash,
			"resubmit-interval", b.builderResubmitInterval.String())
		err := b.eth.BuildBlock(attrs, blockHook, constraints)
		if err != nil {
			log.Warn("Failed to build block", "err", err)
		}
	})
}

func executableDataToExecutionPayload(data *engine.ExecutionPayloadEnvelope, version spec.DataVersion) (*builderApi.VersionedSubmitBlindedBlockResponse, error) {
	// if version in phase0, altair, unsupported version
	if version == spec.DataVersionUnknown || version == spec.DataVersionPhase0 || version == spec.DataVersionAltair {
		return nil, fmt.Errorf("unsupported data version %d", version)
	}

	payload := data.ExecutionPayload
	blobsBundle := data.BlobsBundle

	transactionData := make([]bellatrix.Transaction, len(payload.Transactions))
	for i, tx := range payload.Transactions {
		transactionData[i] = bellatrix.Transaction(tx)
	}

	baseFeePerGas := new(boostTypes.U256Str)
	err := baseFeePerGas.FromBig(payload.BaseFeePerGas)
	if err != nil {
		return nil, err
	}

	if version == spec.DataVersionBellatrix {
		return getBellatrixPayload(payload, *baseFeePerGas, transactionData), nil
	}

	withdrawalData := make([]*capella.Withdrawal, len(payload.Withdrawals))
	for i, wd := range payload.Withdrawals {
		withdrawalData[i] = &capella.Withdrawal{
			Index:          capella.WithdrawalIndex(wd.Index),
			ValidatorIndex: phase0.ValidatorIndex(wd.Validator),
			Address:        bellatrix.ExecutionAddress(wd.Address),
			Amount:         phase0.Gwei(wd.Amount),
		}
	}
	if version == spec.DataVersionCapella {
		return getCapellaPayload(payload, *baseFeePerGas, transactionData, withdrawalData), nil
	}

	uint256BaseFeePerGas, overflow := uint256.FromBig(payload.BaseFeePerGas)
	if overflow {
		return nil, fmt.Errorf("base fee per gas overflow")
	}

	if len(blobsBundle.Blobs) != len(blobsBundle.Commitments) || len(blobsBundle.Blobs) != len(blobsBundle.Proofs) {
		return nil, fmt.Errorf("blobs bundle length mismatch")
	}

	if version == spec.DataVersionDeneb {
		return getDenebPayload(payload, uint256BaseFeePerGas, transactionData, withdrawalData, blobsBundle), nil
	}

	return nil, fmt.Errorf("unsupported data version %d", version)
}

func getBellatrixPayload(
	payload *engine.ExecutableData,
	baseFeePerGas [32]byte,
	transactions []bellatrix.Transaction,
) *builderApi.VersionedSubmitBlindedBlockResponse {
	return &builderApi.VersionedSubmitBlindedBlockResponse{
		Version: spec.DataVersionBellatrix,
		Bellatrix: &bellatrix.ExecutionPayload{
			ParentHash:    [32]byte(payload.ParentHash),
			FeeRecipient:  [20]byte(payload.FeeRecipient),
			StateRoot:     [32]byte(payload.StateRoot),
			ReceiptsRoot:  [32]byte(payload.ReceiptsRoot),
			LogsBloom:     types.BytesToBloom(payload.LogsBloom),
			PrevRandao:    [32]byte(payload.Random),
			BlockNumber:   payload.Number,
			GasLimit:      payload.GasLimit,
			GasUsed:       payload.GasUsed,
			Timestamp:     payload.Timestamp,
			ExtraData:     payload.ExtraData,
			BaseFeePerGas: baseFeePerGas,
			BlockHash:     [32]byte(payload.BlockHash),
			Transactions:  transactions,
		},
	}
}

func getCapellaPayload(
	payload *engine.ExecutableData,
	baseFeePerGas [32]byte,
	transactions []bellatrix.Transaction,
	withdrawals []*capella.Withdrawal,
) *builderApi.VersionedSubmitBlindedBlockResponse {
	return &builderApi.VersionedSubmitBlindedBlockResponse{
		Version: spec.DataVersionCapella,
		Capella: &capella.ExecutionPayload{
			ParentHash:    [32]byte(payload.ParentHash),
			FeeRecipient:  [20]byte(payload.FeeRecipient),
			StateRoot:     [32]byte(payload.StateRoot),
			ReceiptsRoot:  [32]byte(payload.ReceiptsRoot),
			LogsBloom:     types.BytesToBloom(payload.LogsBloom),
			PrevRandao:    [32]byte(payload.Random),
			BlockNumber:   payload.Number,
			GasLimit:      payload.GasLimit,
			GasUsed:       payload.GasUsed,
			Timestamp:     payload.Timestamp,
			ExtraData:     payload.ExtraData,
			BaseFeePerGas: baseFeePerGas,
			BlockHash:     [32]byte(payload.BlockHash),
			Transactions:  transactions,
			Withdrawals:   withdrawals,
		},
	}
}

func getBlobsBundle(blobsBundle *engine.BlobsBundleV1) *builderApiDeneb.BlobsBundle {
	commitments := make([]deneb.KZGCommitment, len(blobsBundle.Commitments))
	proofs := make([]deneb.KZGProof, len(blobsBundle.Proofs))
	blobs := make([]deneb.Blob, len(blobsBundle.Blobs))

	// we assume the lengths for blobs bundle is validated beforehand to be the same
	for i := range blobsBundle.Blobs {
		var commitment deneb.KZGCommitment
		copy(commitment[:], blobsBundle.Commitments[i][:])
		commitments[i] = commitment

		var proof deneb.KZGProof
		copy(proof[:], blobsBundle.Proofs[i][:])
		proofs[i] = proof

		var blob deneb.Blob
		copy(blob[:], blobsBundle.Blobs[i][:])
		blobs[i] = blob
	}
	return &builderApiDeneb.BlobsBundle{
		Commitments: commitments,
		Proofs:      proofs,
		Blobs:       blobs,
	}
}

func getDenebPayload(
	payload *engine.ExecutableData,
	baseFeePerGas *uint256.Int,
	transactions []bellatrix.Transaction,
	withdrawals []*capella.Withdrawal,
	blobsBundle *engine.BlobsBundleV1,
) *builderApi.VersionedSubmitBlindedBlockResponse {
	return &builderApi.VersionedSubmitBlindedBlockResponse{
		Version: spec.DataVersionDeneb,
		Deneb: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
			ExecutionPayload: &deneb.ExecutionPayload{
				ParentHash:    [32]byte(payload.ParentHash),
				FeeRecipient:  [20]byte(payload.FeeRecipient),
				StateRoot:     [32]byte(payload.StateRoot),
				ReceiptsRoot:  [32]byte(payload.ReceiptsRoot),
				LogsBloom:     types.BytesToBloom(payload.LogsBloom),
				PrevRandao:    [32]byte(payload.Random),
				BlockNumber:   payload.Number,
				GasLimit:      payload.GasLimit,
				GasUsed:       payload.GasUsed,
				Timestamp:     payload.Timestamp,
				ExtraData:     payload.ExtraData,
				BaseFeePerGas: baseFeePerGas,
				BlockHash:     [32]byte(payload.BlockHash),
				Transactions:  transactions,
				Withdrawals:   withdrawals,
				BlobGasUsed:   *payload.BlobGasUsed,
				ExcessBlobGas: *payload.ExcessBlobGas,
			},
			BlobsBundle: getBlobsBundle(blobsBundle),
		},
	}
}
