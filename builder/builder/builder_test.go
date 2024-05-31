package builder

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	utilbellatrix "github.com/attestantio/go-eth2-client/util/bellatrix"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/flashbotsextra"
	"github.com/ethereum/go-ethereum/log"
	fastSsz "github.com/ferranbt/fastssz"
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

func TestBlockWithPreconfs(t *testing.T) {
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

	// This is a valid non-preconf tx
	// https://etherscan.io/tx/0x25b8aaba23575f544582e9326c30ed3808d52cb6edc123431bbcacf74c40e96c
	testTxBytes, err := hex.DecodeString("02f8710183089bc58085031b0c4ab082565f94388c818ca8b9251b393131c08a736a67ccb19297873999b89a7354a180c080a08f75074cc97b5b3e16f227bcf7150f2c45e8144057d3f8ed569e4d2b19604fc1a011691495eadf62c47312bf8f8ef2283078f22716ff07f14d382b8b557c1faf80")
	if err != nil {
		t.Fatal(err)
	}

	preconfTxBytes, err := hex.DecodeString("02f8710183089be4808502e2898e638252089487b3f3c934a13c779e100a5d6e6d7ef577e86671876c64fb0212934e80c080a0756aae55edab901f50a206447f0ccf8418835d0245707deb5f7b3a24accb864ba076da473e398a4a2149881462edaf4bd824587d14633ed262b45a54ca8be49e7d")
	require.NoError(t, err)
	preconfTx := new(types.Transaction)
	err = preconfTx.UnmarshalBinary(preconfTxBytes)
	require.NoError(t, err)

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

		BlockHash: common.HexToHash("e7ec4675c311a8bf7e96d3ace8bdf909bec2b6605ab5dc444fc6d0ebe75a5859"),
		// We need to add the preconf here already because test block building doesn't follow
		// the usual flow unfortunately
		Transactions: [][]byte{preconfTxBytes, testTxBytes},
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

	testEthService := &testEthereumService{
		synced:             true,
		testExecutableData: testExecutableData,
		testBlock:          testBlock,
		testBlockValue:     big.NewInt(10),
		testPreconfs:       []*types.Transaction{preconfTx},
	}

	builderArgs := BuilderArgs{
		sk:                           sk,
		ds:                           flashbotsextra.NilDbService{},
		relay:                        &testRelay,
		builderSigningDomain:         bDomain,
		eth:                          testEthService,
		dryRun:                       false,
		ignoreLatePayloadAttributes:  false,
		validator:                    nil,
		beaconClient:                 &testBeacon,
		limiter:                      nil,
		blockConsumer:                flashbotsextra.NilDbService{},
		builderBlockResubmitInterval: 500 * time.Millisecond,
	}
	builder, err := NewBuilder(builderArgs)
	require.NoError(t, err)
	builder.Start()
	defer builder.Stop()

	err = builder.OnPayloadAttribute(testPayloadAttributes)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	require.NotNil(t, testRelay.submittedMsgWithPreconf)

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
	copy(expectedMessage.BlockHash[:], hexutil.MustDecode("0xe7ec4675c311a8bf7e96d3ace8bdf909bec2b6605ab5dc444fc6d0ebe75a5859")[:])
	require.NotNil(t, testRelay.submittedMsgWithPreconf)
	require.Equal(t, expectedMessage, *testRelay.submittedMsgWithPreconf.Inner.Bellatrix.Message)

	t.Log("Message received from relay", testRelay.submittedMsgWithPreconf)

	expectedTxs := make([]bellatrix.Transaction, 0, 2)
	expectedTxs = append(expectedTxs, preconfTxBytes, testTxBytes)

	// In this payload we expect the preconf as first (Top of Block) and then
	// other transactions
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
		Transactions:  expectedTxs,
	}

	require.Equal(t, expectedExecutionPayload, *testRelay.submittedMsgWithPreconf.Inner.Bellatrix.ExecutionPayload)

	expectedSignature, err := utils.HexToSignature("0x920e7e48983bf94b172c2ae847beb00a402440b4c70ba106065a0be2de7fca62aa52e3b04feeb7c571241bb427fe23100ecb2e10dd0bf1442d9e98b3e025b0317eb95da3c6d8447f2a6b3a8f425a01c444d1e2b49ddde56e1b1123454499b5d2")

	require.NoError(t, err)
	require.Equal(t, expectedSignature, testRelay.submittedMsgWithPreconf.Inner.Bellatrix.Signature)

	require.Equal(t, uint64(25), testRelay.requestedSlot)

	// Clear the submitted message and check that the job will be ran again and but a new message will not be submitted since the hash is the same
	testEthService.testBlockValue = big.NewInt(10)

	testRelay.submittedMsgWithPreconf = nil
	time.Sleep(2200 * time.Millisecond)
	require.Nil(t, testRelay.submittedMsgWithPreconf)

	// Change the hash, expect to get the block
	testExecutableData.ExtraData = hexutil.MustDecode("0x0042fafd")
	testExecutableData.BlockHash = common.HexToHash("0x92faeefd45e6192dc9265b1f7fb426cd5340e4670b93853801820cd444efb660")
	testBlock, err = engine.ExecutableDataToBlock(*testExecutableData, nil, nil)
	testEthService.testBlockValue = big.NewInt(10)
	require.NoError(t, err)
	testEthService.testBlock = testBlock

	time.Sleep(2200 * time.Millisecond)
	require.NotNil(t, testRelay.submittedMsgWithPreconf)
}

func TestGenerateSSZProofs(t *testing.T) {
	raw := `["0x02f872833018240385e8d4a5100085e8d4a5100082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead8306942080c001a042696cf1ef039cf23f51b8348c7fcda961727dd6350992b06c6139cf2b66ed18a012252715233c0cb9803bf827942f619b4a6857a9bfb214ef2feba983d1b5ed0e","0x02f90176833018242585012a05f2008512a05f2000830249f0946c6340ba1dc72c59197825cd94eccc1f9c67416e80b901040cc7326300000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000008ffb6787e8ad80000000000000000000000000000b77d61ea79c7ea8bfa03d3604ce5eabfb95c2ab20000000000000000000000002c57d1cfc6d5f8e4182a56b4cf75421472ebaea4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000001cd4af4a9bf33474c802d31790a195335f7a9ab8000000000000000000000000d676af79742bcaeb4a71cf62b85d5ba2d1deaf86c001a08d03bdca0c1647263ef73d916e949ccc53284c6fa208c3fa4f9ddfe67d9c45dfa055be5793b42f1818716276033eb36420fa4fb4e3efabd0bbb01c489f7d9cd43c","0x02f86c8330182404801b825208948943545177806ed17b9f23f0a21ee5948ecaa7768701e71eeda00c3080c001a05918a7b26059059e3fc130bfeb42707bcdab9efaabad518f02f062a5d79e0ae7a06c3f27be896c38ed49a6a943050680b8bb1544b77a4df75c62ef75b357b27c7b"]`

	transactionsRaw := new([]string)
	if err := json.Unmarshal([]byte(raw), transactionsRaw); err != nil {
		t.Fatal("failed decoding json txs", err)
	}

	fmt.Println("transactionsRaw", transactionsRaw)

	transactions := make([]bellatrix.Transaction, 0, 10)
	for _, tx := range *transactionsRaw {
		rawBytes, _ := hex.DecodeString(tx[2:])
		transactions = append(transactions, bellatrix.Transaction(rawBytes))
	}

	fmt.Printf("Transactions len %d\n", len(transactions))

	// generate the SSZ transactions root
	rawTxs := utilbellatrix.ExecutionPayloadTransactions{Transactions: transactions}
	sszRootBytes, err := rawTxs.HashTreeRoot()
	if err != nil {
		t.Fatal("failed generating transactions root", err)
	}
	sszRoot := phase0.Root(sszRootBytes)

	t.Log("ssz root: ", sszRoot.String())

	// now get the binary ssz tree
	rootNode, err := rawTxs.GetTree()
	if err != nil {
		t.Fatal("could not get raw txs tree", err)
	}

	t.Logf("rootNode: %x", rootNode.Hash())

	if [32]byte(rootNode.Hash()) != sszRootBytes {
		t.Fatal("SSZ root from tree doesn't match with computed ssz root from raw transactions: ", [32]byte(rootNode.Hash()), sszRootBytes)
	}

	// generate the proof
	IndexTxToProve := 0
	TRANSACTIONS_LIST_DEPTH := 20

	generalizedIndex := int(math.Pow(float64(2), float64(TRANSACTIONS_LIST_DEPTH+1))) + IndexTxToProve
	t.Log("generalizedIndex: ", generalizedIndex)

	proof, err := rootNode.Prove(generalizedIndex)
	require.NoError(t, err)

	t.Logf("proof hashes: %x", proof.Hashes)
	t.Logf("proof leaf: %x", proof.Leaf)
	t.Log("proof index: ", proof.Index)

	// verify the proof
	// computer the hash tree root of the transaction
	rawTxToVerify := Transaction(transactions[IndexTxToProve])
	t.Logf("rawTxToVerify: %x", rawTxToVerify)
	transactionRoot, err := rawTxToVerify.HashTreeRoot()
	require.NoError(t, err)

	t.Logf("transactionRoot %x", transactionRoot)
	if transactionRoot != [32]byte(proof.Leaf) {
		t.Fatal("transaction root doesn't match with proof leaf")
	}

	res, err := fastSsz.VerifyProof(sszRoot[:], proof)

	require.NoError(t, err)
	if !res {
		t.Fatal("proof verification failed")
	}
}

func TestGenerateSSZProofs2(t *testing.T) {
	raw := `["0x02f872833018240385e8d4a5100085e8d4a5100082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead8306942080c001a042696cf1ef039cf23f51b8348c7fcda961727dd6350992b06c6139cf2b66ed18a012252715233c0cb9803bf827942f619b4a6857a9bfb214ef2feba983d1b5ed0e","0x02f90176833018242585012a05f2008512a05f2000830249f0946c6340ba1dc72c59197825cd94eccc1f9c67416e80b901040cc7326300000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000008ffb6787e8ad80000000000000000000000000000b77d61ea79c7ea8bfa03d3604ce5eabfb95c2ab20000000000000000000000002c57d1cfc6d5f8e4182a56b4cf75421472ebaea4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000001cd4af4a9bf33474c802d31790a195335f7a9ab8000000000000000000000000d676af79742bcaeb4a71cf62b85d5ba2d1deaf86c001a08d03bdca0c1647263ef73d916e949ccc53284c6fa208c3fa4f9ddfe67d9c45dfa055be5793b42f1818716276033eb36420fa4fb4e3efabd0bbb01c489f7d9cd43c","0x02f86c8330182404801b825208948943545177806ed17b9f23f0a21ee5948ecaa7768701e71eeda00c3080c001a05918a7b26059059e3fc130bfeb42707bcdab9efaabad518f02f062a5d79e0ae7a06c3f27be896c38ed49a6a943050680b8bb1544b77a4df75c62ef75b357b27c7b"]`
	preconfRaw := "02f872833018240385e8d4a5100085e8d4a5100082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead8306942080c001a042696cf1ef039cf23f51b8348c7fcda961727dd6350992b06c6139cf2b66ed18a012252715233c0cb9803bf827942f619b4a6857a9bfb214ef2feba983d1b5ed0e"

	// prepare the decoded preconf
	preconf := new(types.Transaction)
	bytes, err := hex.DecodeString(preconfRaw)
	require.NoError(t, err)
	err = preconf.UnmarshalBinary(bytes)
	require.NoError(t, err)
	require.NotNil(t, preconf)
	preconfs := []*types.Transaction{preconf}

	transactionsRaw := new([]string)
	err = json.Unmarshal([]byte(raw), transactionsRaw)
	require.NoError(t, err)

	// prepare the entire payload
	payloadTransactions := make([]*types.Transaction, 0, 10)
	for _, tx := range *transactionsRaw {
		rawBytes, _ := hex.DecodeString(tx[2:])
		transaction := new(types.Transaction)
		require.NoError(t, err)
		err = transaction.UnmarshalBinary(rawBytes)
		require.NoError(t, err)
		require.NotNil(t, transaction)
		payloadTransactions = append(payloadTransactions, transaction)
	}

	t.Logf("Transactions: len %d\n", len(payloadTransactions))

	// BUILDER CODE starts here
	if payloadTransactions[0].Hash() != preconf.Hash() {
		t.Fatal("Preconf transaction doesn't match with the first transaction in the payload")
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

	bellatrixPayloadTxs := utilbellatrix.ExecutionPayloadTransactions{Transactions: rawTxs}

	rootNode, err := bellatrixPayloadTxs.GetTree()
	require.NoError(t, err, "could not get raw txs tree")

	t.Logf("rootNode: %x", rootNode.Hash()) // e557527d9e7d97eaf4592637901e02a31c09c27d6076c27970799f418e47deab

	// BOLT: calculate merkle proofs for preconfirmed transactions
	preconfirmationsProofs := make([]*common.PreconfirmationWithProof, 0, len(preconfs))

	for i, preconf := range preconfs {
		// get the index of the preconfirmed transaction in the block
		preconfIndex := slices.IndexFunc(payloadTransactions, func(tx *types.Transaction) bool { return tx.Hash() == preconf.Hash() })
		if preconfIndex == -1 {
			log.Error(fmt.Sprintf("Preconfirmed transaction %s not found", preconf.Hash()))
			log.Error(fmt.Sprintf("block has %v transactions", len(payloadTransactions)))
			continue
		}

		// using our gen index formula: 2 * 2^20 + preconfIndex
		generalizedIndex := int(math.Pow(float64(2), float64(21))) + preconfIndex

		t.Logf("[BOLT]: Calculating merkle proof for preconfirmed transaction %s with index %d. Preconf index: %d",
			preconf.Hash(), generalizedIndex, preconfIndex)

		timeStart := time.Now()
		proof, err := rootNode.Prove(generalizedIndex)
		require.NoError(t, err, "could not generate proof for preconfirmed transaction")

		t.Logf("[BOLT]: Calculated merkle proof for preconf %s in %s", preconf.Hash(), time.Since(timeStart))
		t.Logf("[BOLT]: LEAF: %x, Is leaf nil? %v", proof.Leaf, proof.Leaf == nil)

		merkleProof := new(common.SerializedMerkleProof)
		merkleProof.FromFastSszProof(proof)

		preconfirmationsProofs = append(preconfirmationsProofs, &common.PreconfirmationWithProof{
			TxHash:      phase0.Hash32(preconf.Hash()),
			MerkleProof: merkleProof,
		})

		t.Logf("[BOLT]: Added merkle proof for preconfirmed transaction %s", preconfirmationsProofs[i])
	}

	t.Logf("[BOLT]: Generated %d merkle proofs for preconfirmed transactions", len(preconfirmationsProofs))
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
	for slot := range slots {
		slot := uint64(slot)
		constraints, ok := builder.constraintsCache.Get(slot)
		expected := generateMockConstraintsForSlot(slot)[0].Message.Constraints[0].Tx
		actual := constraints[0].Message.Constraints[0].Tx
		require.Equal(t, expected, actual)
		require.Equal(t, true, ok)
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

func generateMockConstraintsForSlot(slot uint64) common.Constraints {
	rawTx := new(common.HexBytes)
	err := rawTx.UnmarshalJSON([]byte("\"0x02f876018305da308401312d0085041f1196d2825208940c598786c88883ff5e4f461750fad64d3fae54268804b7ec32d7a2000080c080a0086f02eacec72820be3b117e1edd5bd7ed8956964b28b2d903d2cba53dd13560a06d61ec9ccce6acb31bf21878b9a844e7fdac860c5b7d684f7eb5f38a5945357c\""))
	if err != nil {
		fmt.Println("Failed to unmarshal rawTx: ", err)
	}
	return common.Constraints{
		&common.ConstraintSigned{
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
