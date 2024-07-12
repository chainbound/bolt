package builder

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/flashbotsextra"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/gorilla/handlers"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestOnPayloadAttributes(t *testing.T) {
	const (
		validatorDesiredGasLimit = 30_000_000
		payloadAttributeGasLimit = 0
		parentBlockGasLimit      = 29_000_000
	)
	expectedGasLimit := core.CalcGasLimit(parentBlockGasLimit, validatorDesiredGasLimit)

	vsk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x370bb8c1a6e62b2882f6ec76762a67b39609002076b95aae5b023997cf9b2dc9"))
	require.NoError(t, err)
	validator := &ValidatorPrivateData{
		sk: vsk,
		Pk: hexutil.MustDecode("0xb67d2c11bcab8c4394fc2faa9601d0b99c7f4b37e14911101da7d97077917862eed4563203d34b91b5cf0aa44d6cfa05"),
	}

	testBeacon := testBeaconClient{
		validator: validator,
		slot:      56,
	}

	feeRecipient, _ := utils.HexToAddress("0xabcf8e0d4e9587369b2301d0790347320302cc00")
	testRelay := testRelay{
		gvsVd: ValidatorData{
			Pubkey:       PubkeyHex(testBeacon.validator.Pk.String()),
			FeeRecipient: feeRecipient,
			GasLimit:     validatorDesiredGasLimit,
		},
	}

	sk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x31ee185dad1220a8c88ca5275e64cf5a5cb09cb621cb30df52c9bee8fbaaf8d7"))
	require.NoError(t, err)

	bDomain := ssz.ComputeDomain(ssz.DomainTypeAppBuilder, [4]byte{0x02, 0x0, 0x0, 0x0}, phase0.Root{})

	testExecutableData := &engine.ExecutableData{
		ParentHash:   common.Hash{0x02, 0x03},
		FeeRecipient: common.Address(feeRecipient),
		StateRoot:    common.Hash{0x07, 0x16},
		ReceiptsRoot: common.Hash{0x08, 0x20},
		LogsBloom:    types.Bloom{}.Bytes(),
		Number:       uint64(10),
		GasLimit:     expectedGasLimit,
		GasUsed:      uint64(100),
		Timestamp:    uint64(105),
		ExtraData:    hexutil.MustDecode("0x0042fafc"),

		BaseFeePerGas: big.NewInt(16),

		BlockHash:    common.HexToHash("0x68e516c8827b589fcb749a9e672aa16b9643437459508c467f66a9ed1de66a6c"),
		Transactions: [][]byte{},
	}

	testBlock, err := engine.ExecutableDataToBlock(*testExecutableData, nil, nil)
	require.NoError(t, err)

	testPayloadAttributes := &types.BuilderPayloadAttributes{
		Timestamp:             hexutil.Uint64(104),
		Random:                common.Hash{0x05, 0x10},
		SuggestedFeeRecipient: common.Address{0x04, 0x10},
		GasLimit:              uint64(payloadAttributeGasLimit),
		Slot:                  uint64(25),
	}

	testEthService := &testEthereumService{synced: true, testExecutableData: testExecutableData, testBlock: testBlock, testBlockValue: big.NewInt(10)}
	builderArgs := BuilderArgs{
		sk:                          sk,
		ds:                          flashbotsextra.NilDbService{},
		relay:                       &testRelay,
		builderSigningDomain:        bDomain,
		eth:                         testEthService,
		dryRun:                      false,
		ignoreLatePayloadAttributes: false,
		validator:                   nil,
		beaconClient:                &testBeacon,
		limiter:                     nil,
		blockConsumer:               flashbotsextra.NilDbService{},
	}
	builder, err := NewBuilder(builderArgs)
	require.NoError(t, err)
	builder.Start()
	defer builder.Stop()

	err = builder.OnPayloadAttribute(testPayloadAttributes)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	require.NotNil(t, testRelay.submittedMsg)

	expectedProposerPubkey, err := utils.HexToPubkey(testBeacon.validator.Pk.String())
	require.NoError(t, err)

	expectedMessage := builderApiV1.BidTrace{
		Slot:                 uint64(25),
		ParentHash:           phase0.Hash32{0x02, 0x03},
		BuilderPubkey:        builder.builderPublicKey,
		ProposerPubkey:       expectedProposerPubkey,
		ProposerFeeRecipient: feeRecipient,
		GasLimit:             expectedGasLimit,
		GasUsed:              uint64(100),
		Value:                &uint256.Int{0x0a},
	}
	copy(expectedMessage.BlockHash[:], hexutil.MustDecode("0x68e516c8827b589fcb749a9e672aa16b9643437459508c467f66a9ed1de66a6c")[:])
	require.NotNil(t, testRelay.submittedMsg.Bellatrix)
	require.Equal(t, expectedMessage, *testRelay.submittedMsg.Bellatrix.Message)

	expectedExecutionPayload := bellatrix.ExecutionPayload{
		ParentHash:    [32]byte(testExecutableData.ParentHash),
		FeeRecipient:  feeRecipient,
		StateRoot:     [32]byte(testExecutableData.StateRoot),
		ReceiptsRoot:  [32]byte(testExecutableData.ReceiptsRoot),
		LogsBloom:     [256]byte{},
		PrevRandao:    [32]byte(testExecutableData.Random),
		BlockNumber:   testExecutableData.Number,
		GasLimit:      testExecutableData.GasLimit,
		GasUsed:       testExecutableData.GasUsed,
		Timestamp:     testExecutableData.Timestamp,
		ExtraData:     hexutil.MustDecode("0x0042fafc"),
		BaseFeePerGas: [32]byte{0x10},
		BlockHash:     expectedMessage.BlockHash,
		Transactions:  []bellatrix.Transaction{},
	}

	require.Equal(t, expectedExecutionPayload, *testRelay.submittedMsg.Bellatrix.ExecutionPayload)

	expectedSignature, err := utils.HexToSignature("0x8d1dc346d469b0678ee72baa559315433af0966d2d05dad0de9ce60ff5e4954d4e28a85643496df279494d105bc4a771034fefcdd83d71df5f1b81c9369942b20d6d574b544a93588f6182ba8b09585eb1cf3e1b6551ccbd9e76a4db8eb579fe")

	require.NoError(t, err)
	require.Equal(t, expectedSignature, testRelay.submittedMsg.Bellatrix.Signature)

	require.Equal(t, uint64(25), testRelay.requestedSlot)

	// Clear the submitted message and check that the job will be ran again and but a new message will not be submitted since the hash is the same
	testEthService.testBlockValue = big.NewInt(10)

	testRelay.submittedMsg = nil
	time.Sleep(2200 * time.Millisecond)
	require.Nil(t, testRelay.submittedMsg)

	// Change the hash, expect to get the block
	testExecutableData.ExtraData = hexutil.MustDecode("0x0042fafd")
	testExecutableData.BlockHash = common.HexToHash("0x6a259b9a148da3cc0bf139eaa89292fa9f7b136cfeddad17f7cb0ae33e0c3df9")
	testBlock, err = engine.ExecutableDataToBlock(*testExecutableData, nil, nil)
	testEthService.testBlockValue = big.NewInt(10)
	require.NoError(t, err)
	testEthService.testBlock = testBlock

	time.Sleep(2200 * time.Millisecond)
	require.NotNil(t, testRelay.submittedMsg)
}

func TestOnPayloadAttributesConstraint(t *testing.T) {
	const (
		validatorDesiredGasLimit = 30_000_000
		payloadAttributeGasLimit = 30_000_000 // Was zero in the other test
		parentBlockGasLimit      = 29_000_000
	)
	expectedGasLimit := core.CalcGasLimit(parentBlockGasLimit, validatorDesiredGasLimit)

	vsk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x370bb8c1a6e62b2882f6ec76762a67b39609002076b95aae5b023997cf9b2dc9"))
	require.NoError(t, err)
	validator := &ValidatorPrivateData{
		sk: vsk,
		Pk: hexutil.MustDecode("0xb67d2c11bcab8c4394fc2faa9601d0b99c7f4b37e14911101da7d97077917862eed4563203d34b91b5cf0aa44d6cfa05"),
	}

	testBeacon := testBeaconClient{
		validator: validator,
		slot:      56,
	}

	feeRecipient, _ := utils.HexToAddress("0xabcf8e0d4e9587369b2301d0790347320302cc00")
	testRelay := testRelay{
		gvsVd: ValidatorData{
			Pubkey:       PubkeyHex(testBeacon.validator.Pk.String()),
			FeeRecipient: feeRecipient,
			GasLimit:     validatorDesiredGasLimit,
		},
	}

	sk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x31ee185dad1220a8c88ca5275e64cf5a5cb09cb621cb30df52c9bee8fbaaf8d7"))
	require.NoError(t, err)

	bDomain := ssz.ComputeDomain(ssz.DomainTypeAppBuilder, [4]byte{0x02, 0x0, 0x0, 0x0}, phase0.Root{})

	testExecutableData := &engine.ExecutableData{
		ParentHash:   common.Hash{0x02, 0x03},
		FeeRecipient: common.Address(feeRecipient),
		StateRoot:    common.Hash{0x07, 0x16},
		ReceiptsRoot: common.Hash{0x08, 0x20},
		LogsBloom:    types.Bloom{}.Bytes(),
		Number:       uint64(10),
		GasLimit:     expectedGasLimit,
		GasUsed:      uint64(100),
		Timestamp:    uint64(105),
		ExtraData:    hexutil.MustDecode("0x0042fafc"),

		BaseFeePerGas: big.NewInt(16),

		BlockHash:    common.HexToHash("0x68e516c8827b589fcb749a9e672aa16b9643437459508c467f66a9ed1de66a6c"),
		Transactions: [][]byte{},
	}

	testBlock, err := engine.ExecutableDataToBlock(*testExecutableData, nil, nil)
	require.NoError(t, err)

	testPayloadAttributes := &types.BuilderPayloadAttributes{
		Timestamp:             hexutil.Uint64(104),
		Random:                common.Hash{0x05, 0x10},
		SuggestedFeeRecipient: common.Address{0x04, 0x10},
		GasLimit:              uint64(payloadAttributeGasLimit),
		Slot:                  uint64(25),
	}

	testEthService := &testEthereumService{synced: true, testExecutableData: testExecutableData, testBlock: testBlock, testBlockValue: big.NewInt(10)}
	builderArgs := BuilderArgs{
		sk:                          sk,
		ds:                          flashbotsextra.NilDbService{},
		relay:                       &testRelay,
		builderSigningDomain:        bDomain,
		eth:                         testEthService,
		dryRun:                      false,
		ignoreLatePayloadAttributes: false,
		validator:                   nil,
		beaconClient:                &testBeacon,
		limiter:                     nil,
		blockConsumer:               flashbotsextra.NilDbService{},
	}
	builder, err := NewBuilder(builderArgs)
	require.NoError(t, err)

	tx := createSampleBlobTransaction()

	// Add the transaction to the cache directly
	builder.constraintsCache.Put(25, map[common.Hash]*types.ConstraintDecoded{
		tx.Hash(): {
			Tx: tx,
		},
	})

	builder.Start()
	defer builder.Stop()

	err = builder.OnPayloadAttribute(testPayloadAttributes)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	require.NotNil(t, testRelay.submittedMsgWithPreconf)

	// expectedProposerPubkey, err := utils.HexToPubkey(testBeacon.validator.Pk.String())
	// require.NoError(t, err)

	// expectedMessage := builderApiV1.BidTrace{
	// 	Slot:                 uint64(25),
	// 	ParentHash:           phase0.Hash32{0x02, 0x03},
	// 	BuilderPubkey:        builder.builderPublicKey,
	// 	ProposerPubkey:       expectedProposerPubkey,
	// 	ProposerFeeRecipient: feeRecipient,
	// 	GasLimit:             expectedGasLimit,
	// 	GasUsed:              uint64(100),
	// 	Value:                &uint256.Int{0x0a},
	// }
	// copy(expectedMessage.BlockHash[:], hexutil.MustDecode("0x68e516c8827b589fcb749a9e672aa16b9643437459508c467f66a9ed1de66a6c")[:])
	// require.NotNil(t, testRelay.submittedMsgWithPreconf)
	// require.Equal(t, expectedMessage, *testRelay.submittedMsgWithPreconf.Bellatrix.Message)

	// expectedExecutionPayload := bellatrix.ExecutionPayload{
	// 	ParentHash:    [32]byte(testExecutableData.ParentHash),
	// 	FeeRecipient:  feeRecipient,
	// 	StateRoot:     [32]byte(testExecutableData.StateRoot),
	// 	ReceiptsRoot:  [32]byte(testExecutableData.ReceiptsRoot),
	// 	LogsBloom:     [256]byte{},
	// 	PrevRandao:    [32]byte(testExecutableData.Random),
	// 	BlockNumber:   testExecutableData.Number,
	// 	GasLimit:      testExecutableData.GasLimit,
	// 	GasUsed:       testExecutableData.GasUsed,
	// 	Timestamp:     testExecutableData.Timestamp,
	// 	ExtraData:     hexutil.MustDecode("0x0042fafc"),
	// 	BaseFeePerGas: [32]byte{0x10},
	// 	BlockHash:     expectedMessage.BlockHash,
	// 	Transactions:  []bellatrix.Transaction{},
	// }

	// require.Equal(t, expectedExecutionPayload, *testRelay.submittedMsg.Bellatrix.ExecutionPayload)

	// expectedSignature, err := utils.HexToSignature("0x8d1dc346d469b0678ee72baa559315433af0966d2d05dad0de9ce60ff5e4954d4e28a85643496df279494d105bc4a771034fefcdd83d71df5f1b81c9369942b20d6d574b544a93588f6182ba8b09585eb1cf3e1b6551ccbd9e76a4db8eb579fe")

	// require.NoError(t, err)
	// require.Equal(t, expectedSignature, testRelay.submittedMsg.Bellatrix.Signature)

	// require.Equal(t, uint64(25), testRelay.requestedSlot)

	// // Clear the submitted message and check that the job will be ran again and but a new message will not be submitted since the hash is the same
	// testEthService.testBlockValue = big.NewInt(10)

	// testRelay.submittedMsg = nil
	// time.Sleep(2200 * time.Millisecond)
	// require.Nil(t, testRelay.submittedMsg)

	// // Change the hash, expect to get the block
	// testExecutableData.ExtraData = hexutil.MustDecode("0x0042fafd")
	// testExecutableData.BlockHash = common.HexToHash("0x6a259b9a148da3cc0bf139eaa89292fa9f7b136cfeddad17f7cb0ae33e0c3df9")
	// testBlock, err = engine.ExecutableDataToBlock(*testExecutableData, nil, nil)
	// testEthService.testBlockValue = big.NewInt(10)
	// require.NoError(t, err)
	// testEthService.testBlock = testBlock

	// time.Sleep(2200 * time.Millisecond)
	// require.NotNil(t, testRelay.submittedMsg)
}

func TestSubscribeProposerConstraints(t *testing.T) {
	// ------------ Start Builder setup ------------- //
	const (
		validatorDesiredGasLimit = 30_000_000
		payloadAttributeGasLimit = 0
		parentBlockGasLimit      = 29_000_000
	)
	expectedGasLimit := core.CalcGasLimit(parentBlockGasLimit, validatorDesiredGasLimit)

	vsk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x370bb8c1a6e62b2882f6ec76762a67b39609002076b95aae5b023997cf9b2dc9"))
	require.NoError(t, err)
	validator := &ValidatorPrivateData{
		sk: vsk,
		Pk: hexutil.MustDecode("0xb67d2c11bcab8c4394fc2faa9601d0b99c7f4b37e14911101da7d97077917862eed4563203d34b91b5cf0aa44d6cfa05"),
	}

	testBeacon := testBeaconClient{
		validator: validator,
		slot:      56,
	}

	feeRecipient, _ := utils.HexToAddress("0xabcf8e0d4e9587369b2301d0790347320302cc00")

	relayPort := "31245"
	relay := NewRemoteRelay(RelayConfig{Endpoint: "http://localhost:" + relayPort}, nil, true)

	sk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x31ee185dad1220a8c88ca5275e64cf5a5cb09cb621cb30df52c9bee8fbaaf8d7"))
	require.NoError(t, err)

	bDomain := ssz.ComputeDomain(ssz.DomainTypeAppBuilder, [4]byte{0x02, 0x0, 0x0, 0x0}, phase0.Root{})

	testExecutableData := &engine.ExecutableData{
		ParentHash:   common.Hash{0x02, 0x03},
		FeeRecipient: common.Address(feeRecipient),
		StateRoot:    common.Hash{0x07, 0x16},
		ReceiptsRoot: common.Hash{0x08, 0x20},
		LogsBloom:    types.Bloom{}.Bytes(),
		Number:       uint64(10),
		GasLimit:     expectedGasLimit,
		GasUsed:      uint64(100),
		Timestamp:    uint64(105),
		ExtraData:    hexutil.MustDecode("0x0042fafc"),

		BaseFeePerGas: big.NewInt(16),

		BlockHash:    common.HexToHash("0x68e516c8827b589fcb749a9e672aa16b9643437459508c467f66a9ed1de66a6c"),
		Transactions: [][]byte{},
	}

	testBlock, err := engine.ExecutableDataToBlock(*testExecutableData, nil, nil)
	require.NoError(t, err)

	testEthService := &testEthereumService{synced: true, testExecutableData: testExecutableData, testBlock: testBlock, testBlockValue: big.NewInt(10)}

	builderArgs := BuilderArgs{
		sk:                          sk,
		ds:                          flashbotsextra.NilDbService{},
		relay:                       relay,
		builderSigningDomain:        bDomain,
		eth:                         testEthService,
		dryRun:                      false,
		ignoreLatePayloadAttributes: false,
		validator:                   nil,
		beaconClient:                &testBeacon,
		limiter:                     nil,
		blockConsumer:               flashbotsextra.NilDbService{},
	}

	builder, err := NewBuilder(builderArgs)
	require.NoError(t, err)

	// ------------ End Builder setup ------------- //

	// Attach the sseHandler to the relay port
	mux := http.NewServeMux()
	mux.HandleFunc(SubscribeConstraintsPath, sseConstraintsHandler)

	// Wrap the mux with the GzipHandler middleware
	// NOTE: In this case, we don't need to create a gzip writer in the handlers,
	// by default the `http.ResponseWriter` will implement gzip compression
	gzipMux := handlers.CompressHandler(mux)

	http.HandleFunc(SubscribeConstraintsPath, sseConstraintsHandler)
	go http.ListenAndServe(":"+relayPort, gzipMux)

	// Constraints should not be available yet
	_, ok := builder.constraintsCache.Get(0)
	require.Equal(t, false, ok)

	// Create authentication signed message
	authHeader, err := builder.GenerateAuthenticationHeader()
	require.NoError(t, err)
	builder.subscribeToRelayForConstraints(builder.relay.Config().Endpoint, authHeader)
	// Wait 2 seconds to save all constraints in cache
	time.Sleep(2 * time.Second)

	slots := []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	for _, slot := range slots {
		cachedConstraints, ok := builder.constraintsCache.Get(slot)
		require.Equal(t, true, ok)

		expectedConstraint := generateMockConstraintsForSlot(slot)[0]
		decodedConstraint, err := DecodeConstraints(expectedConstraint)
		require.NoError(t, err)

		// Compare the keys of the cachedConstraints and decodedConstraint maps
		require.Equal(t, len(cachedConstraints), len(decodedConstraint), "The number of keys in both maps should be the same")
		for key := range cachedConstraints {
			_, ok := decodedConstraint[key]
			require.True(t, ok, fmt.Sprintf("Key %s found in cachedConstraints but not in decodedConstraint", key.String()))
			require.Equal(t, cachedConstraints[key].Tx.Data(), decodedConstraint[key].Tx.Data(), "The decodedConstraint Tx should be equal to the cachedConstraints Tx")
		}
		for key := range decodedConstraint {
			_, ok := cachedConstraints[key]
			require.True(t, ok, fmt.Sprintf("Key %s found in decodedConstraint but not in cachedConstraints", key.String()))
		}
	}
}

func sseConstraintsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Content-Encoding", "gzip")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	auth := r.Header.Get("Authorization")
	_, err := validateConstraintSubscriptionAuth(auth, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	for i := 0; i < 256; i++ {
		// Generate some duplicated constraints
		slot := uint64(i) % 32
		constraints := generateMockConstraintsForSlot(slot)
		bytes, err := json.Marshal(constraints)
		if err != nil {
			log.Error(fmt.Sprintf("Error while marshaling constraints: %v", err))
			return
		}
		fmt.Fprintf(w, "data: %s\n\n", string(bytes))
		flusher.Flush()
	}
}

// generateMockConstraintsForSlot generates a list of constraints for a given slot
func generateMockConstraintsForSlot(slot uint64) common.SignedConstraintsList {
	rawTx := new(common.HexBytes)
	err := rawTx.UnmarshalJSON([]byte("\"0x02f876018305da308401312d0085041f1196d2825208940c598786c88883ff5e4f461750fad64d3fae54268804b7ec32d7a2000080c080a0086f02eacec72820be3b117e1edd5bd7ed8956964b28b2d903d2cba53dd13560a06d61ec9ccce6acb31bf21878b9a844e7fdac860c5b7d684f7eb5f38a5945357c\""))
	if err != nil {
		fmt.Println("Failed to unmarshal rawTx: ", err)
	}

	return common.SignedConstraintsList{
		&common.SignedConstraints{
			Message: common.ConstraintMessage{
				Constraints: []*common.Constraint{{Tx: *rawTx}}, ValidatorIndex: 0, Slot: slot,
			}, Signature: phase0.BLSSignature{},
		},
	}
}

// validateConstraintSubscriptionAuth checks the authentication string data from the Builder,
// and returns its BLS public key if the authentication is valid.
func validateConstraintSubscriptionAuth(auth string, headSlot uint64) (phase0.BLSPubKey, error) {
	zeroKey := phase0.BLSPubKey{}
	if auth == "" {
		return zeroKey, errors.New("authorization header missing")
	}
	// Authorization: <auth-scheme> <authorization-parameters>
	parts := strings.Split(auth, " ")
	if len(parts) != 2 {
		return zeroKey, errors.New("ill-formed authorization header")
	}
	if parts[0] != "BOLT" {
		return zeroKey, errors.New("not BOLT authentication scheme")
	}
	// <signatureJSON>,<authDataJSON>
	parts = strings.SplitN(parts[1], ",", 2)
	if len(parts) != 2 {
		return zeroKey, errors.New("ill-formed authorization header")
	}

	signature := new(phase0.BLSSignature)
	if err := signature.UnmarshalJSON([]byte(parts[0])); err != nil {
		fmt.Println("Failed to unmarshal authData: ", err)
		return zeroKey, errors.New("ill-formed authorization header")
	}

	authDataRaw := []byte(parts[1])
	authData := new(common.ConstraintSubscriptionAuth)
	if err := json.Unmarshal(authDataRaw, authData); err != nil {
		fmt.Println("Failed to unmarshal authData: ", err)
		return zeroKey, errors.New("ill-formed authorization header")
	}

	if headSlot != authData.Slot {
		return zeroKey, errors.New("invalid head slot")
	}

	ok, err := bls.VerifySignatureBytes(authDataRaw, signature[:], authData.PublicKey[:])
	if err != nil || !ok {
		return zeroKey, errors.New("invalid signature")
	}
	return authData.PublicKey, nil
}

func createSampleBlobTransaction() *types.Transaction {
	// Sample values
	chainID := uint256.NewInt(1)
	nonce := uint64(0)
	gasTipCap := uint256.NewInt(1000000000)  // 1 Gwei
	gasFeeCap := uint256.NewInt(10000000000) // 10 Gwei
	gas := uint64(21000)
	to := common.HexToAddress("0xRecipientAddress")
	value := uint256.NewInt(1000000000000000000) // 1 Ether
	data := []byte{}
	blobFeeCap := uint256.NewInt(1000000000) // 1 Gwei

	// Create blobs, commitments, and proofs
	blobs := []kzg4844.Blob{{}}
	commitments := []kzg4844.Commitment{{}}
	proofs := []kzg4844.Proof{{}}

	// Create the BlobTxSidecar
	sidecar := &types.BlobTxSidecar{
		Blobs:       blobs,
		Commitments: commitments,
		Proofs:      proofs,
	}

	// Create the BlobTx
	blobTx := &types.BlobTx{
		ChainID:    chainID,
		Nonce:      nonce,
		GasTipCap:  gasTipCap,
		GasFeeCap:  gasFeeCap,
		Gas:        gas,
		To:         to,
		Value:      value,
		Data:       data,
		BlobFeeCap: blobFeeCap,
		BlobHashes: sidecar.BlobHashes(),
		Sidecar:    sidecar,
	}

	// Create the transaction
	tx := types.NewTx(blobTx)

	return tx
}
