// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {Utils} from "./Utils.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {BoltParameters} from "../src/contracts/BoltParameters.sol";
import {BoltChallenger} from "../src/contracts/BoltChallenger.sol";
import {BoltConfig} from "../src/lib/Config.sol";
import {IBoltChallenger} from "../src/interfaces/IBoltChallenger.sol";
import {RLPReader} from "../src/lib/rlp/RLPReader.sol";
import {RLPWriter} from "../src/lib/rlp/RLPWriter.sol";
import {BytesUtils} from "../src/lib/BytesUtils.sol";
import {MerkleTrie} from "../src/lib/trie/MerkleTrie.sol";
import {SecureMerkleTrie} from "../src/lib/trie/SecureMerkleTrie.sol";
import {TransactionDecoder} from "../src/lib/TransactionDecoder.sol";

// re-export the internal resolver function for testing
contract BoltChallengerExt is BoltChallenger {
    function _resolveExt(
        bytes32 _challengeID,
        bytes32 _trustedBlockHash,
        IBoltChallenger.Proof calldata _proof
    ) external {
        _resolve(_challengeID, _trustedBlockHash, _proof);
    }

    function _getCurrentSlotExt() external view returns (uint256) {
        return _getCurrentSlot();
    }

    function _decodeBlockHeaderRLPExt(
        bytes calldata _blockHeaderRLP
    ) external pure returns (IBoltChallenger.BlockHeaderData memory) {
        return _decodeBlockHeaderRLP(_blockHeaderRLP);
    }
}

contract BoltChallengerTest is Test {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using BytesUtils for bytes;
    using TransactionDecoder for TransactionDecoder.Transaction;
    using TransactionDecoder for bytes;

    BoltChallengerExt boltChallenger;

    address admin = makeAddr("admin");
    address challenger = makeAddr("challenger");
    address resolver = makeAddr("resolver");

    address target;
    uint256 targetPK;

    function setUp() public {
        vm.pauseGasMetering();
        (target, targetPK) = makeAddrAndKey("target");

        BoltConfig.ParametersConfig memory config = new Utils().readParameters();

        BoltParameters parameters = new BoltParameters();
        parameters.initialize(
            admin,
            config.epochDuration,
            config.slashingWindow,
            config.maxChallengeDuration,
            config.allowUnsafeRegistration,
            config.challengeBond,
            config.blockhashEvmLookback,
            config.justificationDelay,
            config.eth2GenesisTimestamp,
            config.slotTime,
            config.minimumOperatorStake
        );

        boltChallenger = new BoltChallengerExt();
        boltChallenger.initialize(admin, address(parameters));

        vm.deal(challenger, 100 ether);
        vm.deal(resolver, 100 ether);
        vm.roll(12_456_789);
        vm.warp(1_726_564_072);
    }

    // =========== Proving data inclusion on-chain ===========

    function testProveHeaderData() public {
        // Note: In prod, how we obtain the trusted block hash would depend on the context.
        // For recent blocks, we can simply use the blockhash function in the EVM.
        bytes32 trustedBlockHash = 0x0fc7c840f5b4b451e99dc8adb0d475eab2ac7d36278d9601d7f4b2dd05e8022f;

        // Read the RLP-encoded block header from a file (obtained via `debug_getRawHeader` RPC call)
        string memory file = vm.readFile("./test/testdata/header_20785012.json");
        bytes memory headerRLP = vm.parseJsonBytes(file, ".result");

        assertEq(keccak256(headerRLP), trustedBlockHash);

        // RLP decode the header
        vm.resumeGasMetering();
        IBoltChallenger.BlockHeaderData memory header = boltChallenger._decodeBlockHeaderRLPExt(headerRLP);
        vm.pauseGasMetering();

        assertEq(header.stateRoot, 0x214389f55a96edbd4d5295a17ada4dbc68a3b276145bf824b060635f9905cefc);
        assertEq(header.txRoot, 0x87bb9183296ce9e3b7a3246f6d3a778b99a5d7daaba2174750707407c7297365);
        assertEq(header.blockNumber, 20_785_012);
        assertEq(header.timestamp, 1_726_753_391);
        assertEq(header.baseFee, 21_575_309_588);
    }

    function testProveAccountData() public {
        // The account we want to prove
        address accountToProve = 0x0D9f5045B604bA0c050b5eb06D0b25d01c525Ea5;

        // Note: in prod the state root should be obtained from the block header proof.
        // this way we can trust it comes from the right block number. This comes from Mainnet block 20_728_344.
        bytes32 stateRootAtBlock = 0x214389f55a96edbd4d5295a17ada4dbc68a3b276145bf824b060635f9905cefc;

        // Read the RLP-encoded account proof from a file. This is obtained from the `eth_getProof`
        // RPC call + ABI-encoding of the resulting accountProof array.
        string memory file = vm.readFile("./test/testdata/eth_proof_20785012.json");
        bytes[] memory accountProofJson = vm.parseJsonBytesArray(file, ".result.accountProof");
        bytes memory accountProof = _RLPEncodeList(accountProofJson);

        // Perform a sanity check to see if the state root matches the expected trie node
        RLPReader.RLPItem[] memory nodes = RLPReader.readList(accountProof);
        MerkleTrie.TrieNode[] memory proof = new MerkleTrie.TrieNode[](nodes.length);
        for (uint256 i = 0; i < nodes.length; i++) {
            bytes memory encoded = RLPReader.readBytes(nodes[i]);
            proof[i] = MerkleTrie.TrieNode({encoded: encoded, decoded: RLPReader.readList(encoded)});
        }
        assertEq(keccak256(proof[0].encoded), stateRootAtBlock, "Roots should match");

        vm.resumeGasMetering();
        (bool exists, bytes memory accountRLP) =
            SecureMerkleTrie.get(abi.encodePacked(accountToProve), accountProof, stateRootAtBlock);
        vm.pauseGasMetering();
        assertEq(exists, true);

        // decode the account RLP into nonce and balance
        RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();
        uint256 nonce = accountFields[0].readUint256();
        uint256 balance = accountFields[1].readUint256();

        assertEq(nonce, 236);
        assertEq(balance, 136_481_368_234_605_997);
    }

    function testProveTransactionInclusion() public {
        // The transaction we want to prove inclusion of
        bytes32 txHash = 0x9ec2c56ca36e445a46bc77ca77510f0ef21795d00834269f3752cbd29d63ba1f;

        // MPT proof, obtained with the `trie-proofs` CLI tool from HerodotusDev
        // ref: <https://github.com/HerodotusDev/trie-proofs>
        string memory file = vm.readFile("./test/testdata/tx_mpt_proof_20785012.json");
        bytes[] memory txProofJson = vm.parseJsonBytesArray(file, ".proof");
        bytes memory txProof = _RLPEncodeList(txProofJson);

        // The transactions root and index in the block, also included in the CLI response
        bytes32 txRootAtBlock = vm.parseJsonBytes32(file, ".root");
        uint256 txIndexInBlock = vm.parseJsonUint(file, ".index");

        bytes memory key = RLPWriter.writeUint(txIndexInBlock);

        vm.resumeGasMetering();
        // Gotcha: SecureMerkleTrie.get expects the key to be hashed with keccak256
        // but the transaction trie skips this step and uses the raw index as the key.
        (bool exists, bytes memory transactionRLP) = MerkleTrie.get(key, txProof, txRootAtBlock);
        vm.pauseGasMetering();

        assertEq(exists, true);
        assertEq(keccak256(transactionRLP), txHash);

        // Decode the transaction RLP into its fields
        TransactionDecoder.Transaction memory decodedTx = transactionRLP.decodeEnveloped();
        assertEq(uint8(decodedTx.txType), 2);
        assertEq(decodedTx.chainId, 1);
        assertEq(decodedTx.nonce, 0xeb);
        assertEq(decodedTx.maxPriorityFeePerGas, 0x73a20d00);
        assertEq(decodedTx.maxFeePerGas, 0x7e172a822);
        assertEq(decodedTx.gasLimit, 0x5208);
        assertEq(decodedTx.to, 0x0ff71973B5243005b192D5BCF552Fc2532b7bdEc);
        assertEq(decodedTx.value, 0x15842095ebc4000);
        assertEq(decodedTx.data.length, 0);
        assertEq(decodedTx.recoverSender(), 0x0D9f5045B604bA0c050b5eb06D0b25d01c525Ea5);
    }

    // =========== Verifying Signatures ===========

    function testCommitmentDigestAndSignature() public {
        // The test commitment has been created in the Bolt sidecar using the Rust
        // methods to compute the digest() and recover the signer from the signature.
        IBoltChallenger.SignedCommitment memory commitment = _parseTestCommitment();

        // Reconstruct the commitment digest: `keccak( keccak(signed tx) || le_bytes(slot) )`
        bytes32 commitmentID = _computeCommitmentID(commitment.signedTx, commitment.slot);

        assertEq(commitmentID, 0x52ecc7832625c3d107aaba5b55d4509b48cd9f4f7ce375d6696d09bbf3310525);
        assertEq(commitment.signature.length, 65);

        // Verify the commitment signature against the digest
        vm.resumeGasMetering();
        address commitmentSigner = ECDSA.recover(commitmentID, commitment.signature);
        assertEq(commitmentSigner, 0x27083ED52464625660f3e30Aa5B9C20A30D7E110);
        vm.pauseGasMetering();
    }

    function testCommitmentSignature() public {
        bytes memory signedTx = vm.parseJsonBytes(vm.readFile("./test/testdata/signed_tx_20785012_1.json"), ".raw");
        uint64 slot = 20_728_344;

        // Reconstruct the commitment digest
        bytes32 commitmentID = _computeCommitmentID(signedTx, slot);

        // Sign the commitment digest with the target
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(targetPK, commitmentID);
        bytes memory commitmentSignature = abi.encodePacked(r, s, v);

        // Verify the commitment signature against the digest
        vm.resumeGasMetering();
        address commitmentSigner = ECDSA.recover(commitmentID, commitmentSignature);
        assertEq(commitmentSigner, target);
        vm.pauseGasMetering();
    }

    // =========== Opening a challenge ===========

    function testOpenChallengeSingleTx() public {
        IBoltChallenger.SignedCommitment[] memory commitments = new IBoltChallenger.SignedCommitment[](1);
        commitments[0] = _parseTestCommitment();

        assertEq(challenger.balance, 100 ether);

        // Open a challenge with the commitment
        vm.resumeGasMetering();
        vm.prank(challenger);
        boltChallenger.openChallenge{value: 1 ether}(commitments);
        vm.pauseGasMetering();

        assertEq(challenger.balance, 99 ether);

        // Check the challenge was opened
        IBoltChallenger.Challenge[] memory challenges = boltChallenger.getAllChallenges();
        assertEq(challenges.length, 1);

        IBoltChallenger.Challenge memory challenge = challenges[0];
        assertEq(challenge.openedAt, block.timestamp);
        assertEq(uint256(challenge.status), 0);
        assertEq(challenge.challenger, challenger);
        assertEq(challenge.commitmentSigner, 0x27083ED52464625660f3e30Aa5B9C20A30D7E110);
        assertEq(challenge.targetSlot, commitments[0].slot);
    }

    function testOpenChallengeWithIncorrectBond() public {
        IBoltChallenger.SignedCommitment[] memory commitments = new IBoltChallenger.SignedCommitment[](1);
        commitments[0] = _parseTestCommitment();

        // Open a challenge with insufficient bond
        vm.resumeGasMetering();
        vm.prank(challenger);
        vm.expectRevert(IBoltChallenger.IncorrectChallengeBond.selector);
        boltChallenger.openChallenge{value: 0.1 ether}(commitments);
        vm.pauseGasMetering();
    }

    function testOpenChallengeWithLargebond() public {
        IBoltChallenger.SignedCommitment[] memory commitments = new IBoltChallenger.SignedCommitment[](1);
        commitments[0] = _parseTestCommitment();

        // Open a challenge with a large bond, making sure that the rest is refunded
        vm.resumeGasMetering();
        vm.prank(challenger);
        vm.expectRevert(IBoltChallenger.IncorrectChallengeBond.selector);
        boltChallenger.openChallenge{value: 50 ether}(commitments);
        vm.pauseGasMetering();

        assertEq(challenger.balance, 100 ether);
    }

    function testOpenAlreadyExistingChallenge() public {
        IBoltChallenger.SignedCommitment[] memory commitments = new IBoltChallenger.SignedCommitment[](1);
        commitments[0] = _parseTestCommitment();

        // Open a challenge
        vm.prank(challenger);
        boltChallenger.openChallenge{value: 1 ether}(commitments);

        // Try to open the same challenge again
        vm.resumeGasMetering();
        vm.prank(challenger);
        vm.expectRevert(IBoltChallenger.ChallengeAlreadyExists.selector);
        boltChallenger.openChallenge{value: 1 ether}(commitments);
        vm.pauseGasMetering();
    }

    function testOpenChallengeWithSlotInTheFuture() public {
        IBoltChallenger.SignedCommitment[] memory commitments = new IBoltChallenger.SignedCommitment[](1);
        commitments[0] = _parseTestCommitment();

        commitments[0].slot = uint64(boltChallenger._getCurrentSlotExt()) + 10;

        // Open a challenge with a slot in the future
        vm.resumeGasMetering();
        vm.prank(challenger);
        vm.expectRevert(IBoltChallenger.BlockIsNotFinalized.selector);
        boltChallenger.openChallenge{value: 1 ether}(commitments);
        vm.pauseGasMetering();
    }

    function testOpenChallengeInvalidSignature() public {
        IBoltChallenger.SignedCommitment[] memory commitments = new IBoltChallenger.SignedCommitment[](1);
        commitments[0] = _parseTestCommitment();

        // Modify the signature to make it invalid
        commitments[0].signature[0] = bytes1(uint8(commitments[0].signature[0]) + 5);

        // Open a challenge with an invalid signature
        vm.resumeGasMetering();
        vm.prank(challenger);
        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        boltChallenger.openChallenge{value: 1 ether}(commitments);
        vm.pauseGasMetering();
    }

    // =========== Resolving a challenge ===========

    function testResolveChallengeFullDefenseSingleTx() public {
        // Prove the full defense of a challenge: the block headers, account proof, and tx proofs
        // are all valid and the proposer has included the transaction in their slot.

        uint256 inclusionBlockNumber = 20_785_012;
        IBoltChallenger.SignedCommitment[] memory commitments = new IBoltChallenger.SignedCommitment[](1);
        commitments[0] = _createRecentBoltCommitment(inclusionBlockNumber, 1);

        // Open a challenge
        vm.prank(challenger);
        boltChallenger.openChallenge{value: 1 ether}(commitments);

        // Get the challenge ID
        IBoltChallenger.Challenge[] memory challenges = boltChallenger.getAllChallenges();
        assertEq(challenges.length, 1);
        bytes32 challengeID = challenges[0].id;

        string memory rawPreviousHeader = vm.readFile("./test/testdata/header_20785011.json");
        string memory rawInclusionHeader = vm.readFile("./test/testdata/header_20785012.json");
        string memory ethProof = vm.readFile("./test/testdata/eth_proof_20785011.json");
        string memory txProof = vm.readFile("./test/testdata/tx_mpt_proof_20785012.json");

        bytes[] memory txProofs = new bytes[](1);
        txProofs[0] = _RLPEncodeList(vm.parseJsonBytesArray(txProof, ".proof"));

        uint256[] memory txIndexesInBlock = new uint256[](1);
        txIndexesInBlock[0] = vm.parseJsonUint(txProof, ".index");

        IBoltChallenger.Proof memory proof = IBoltChallenger.Proof({
            inclusionBlockNumber: inclusionBlockNumber,
            previousBlockHeaderRLP: vm.parseJsonBytes(rawPreviousHeader, ".result"),
            inclusionBlockHeaderRLP: vm.parseJsonBytes(rawInclusionHeader, ".result"),
            accountMerkleProof: _RLPEncodeList(vm.parseJsonBytesArray(ethProof, ".result.accountProof")),
            txMerkleProofs: txProofs,
            txIndexesInBlock: txIndexesInBlock
        });

        // check that the inclusion block transactions root matches the root in the tx proof data.
        bytes32 inclusionTxRoot = boltChallenger._decodeBlockHeaderRLPExt(proof.inclusionBlockHeaderRLP).txRoot;
        assertEq(inclusionTxRoot, vm.parseJsonBytes32(txProof, ".root"));

        bytes32 trustedPreviousBlockHash = 0x6be050fe1f6c7ffe8f30a350250a9ecc08ff3c031d129f65e1c10e5119d7a28b;

        // Resolve the challenge
        vm.resumeGasMetering();
        vm.prank(resolver);
        vm.expectEmit();

        emit IBoltChallenger.ChallengeDefended(challengeID);
        boltChallenger._resolveExt(challengeID, trustedPreviousBlockHash, proof);
    }

    function testResolveChallengeFullDefenseStackedTxs() public {
        // Prove the full defense of a challenge: the block headers, account proof, and tx proofs
        // are all valid and the proposer has included the transaction in their slot.
        // This time, the proposer has committed to multiple transactions in their slot.
        //
        // The test data for this test was generated by querying for an Ethereum block with a
        // sender that has sent multiple transactions in the same block.
        // Check out https://etherscan.io/block/20817618

        uint256 inclusionBlockNumber = 20_817_618;
        IBoltChallenger.SignedCommitment[] memory commitments = new IBoltChallenger.SignedCommitment[](5);
        commitments[0] = _createRecentBoltCommitment(inclusionBlockNumber, 1);
        commitments[1] = _createRecentBoltCommitment(inclusionBlockNumber, 2);
        commitments[2] = _createRecentBoltCommitment(inclusionBlockNumber, 3);
        commitments[3] = _createRecentBoltCommitment(inclusionBlockNumber, 4);
        commitments[4] = _createRecentBoltCommitment(inclusionBlockNumber, 5);

        // Sanity check senders of the transactions: they should all be the same
        for (uint256 i = 0; i < commitments.length; i++) {
            address recovered = commitments[i].signedTx.decodeEnveloped().recoverSender();
            assertEq(recovered, 0xc21fb45Eeb45D883B838E30ABBd2896aE5AC888c);
        }

        // Sanity check signers of the commitments: they should all be the same
        for (uint256 i = 0; i < commitments.length; i++) {
            bytes32 cid = _computeCommitmentID(commitments[i].signedTx, commitments[i].slot);
            address signer = ECDSA.recover(cid, commitments[i].signature);
            assertEq(signer, target);
        }

        // Open a challenge
        vm.prank(challenger);
        boltChallenger.openChallenge{value: 1 ether}(commitments);

        // Get the challenge ID
        IBoltChallenger.Challenge[] memory challenges = boltChallenger.getAllChallenges();
        assertEq(challenges.length, 1);
        bytes32 challengeID = challenges[0].id;

        // headers
        string memory rawPreviousHeader = vm.readFile("./test/testdata/header_20817617.json");
        string memory rawInclusionHeader = vm.readFile("./test/testdata/header_20817618.json");

        // account
        string memory ethProof = vm.readFile("./test/testdata/eth_proof_20817617.json");

        // transactions
        string memory txProof1 = vm.readFile("./test/testdata/tx_mpt_proof_20817618_1.json");
        string memory txProof2 = vm.readFile("./test/testdata/tx_mpt_proof_20817618_2.json");
        string memory txProof3 = vm.readFile("./test/testdata/tx_mpt_proof_20817618_3.json");
        string memory txProof4 = vm.readFile("./test/testdata/tx_mpt_proof_20817618_4.json");
        string memory txProof5 = vm.readFile("./test/testdata/tx_mpt_proof_20817618_5.json");

        bytes[] memory txProofs = new bytes[](5);
        txProofs[0] = _RLPEncodeList(vm.parseJsonBytesArray(txProof1, ".proof"));
        txProofs[1] = _RLPEncodeList(vm.parseJsonBytesArray(txProof2, ".proof"));
        txProofs[2] = _RLPEncodeList(vm.parseJsonBytesArray(txProof3, ".proof"));
        txProofs[3] = _RLPEncodeList(vm.parseJsonBytesArray(txProof4, ".proof"));
        txProofs[4] = _RLPEncodeList(vm.parseJsonBytesArray(txProof5, ".proof"));

        uint256[] memory txIndexesInBlock = new uint256[](5);
        txIndexesInBlock[0] = vm.parseJsonUint(txProof1, ".index");
        txIndexesInBlock[1] = vm.parseJsonUint(txProof2, ".index");
        txIndexesInBlock[2] = vm.parseJsonUint(txProof3, ".index");
        txIndexesInBlock[3] = vm.parseJsonUint(txProof4, ".index");
        txIndexesInBlock[4] = vm.parseJsonUint(txProof5, ".index");

        IBoltChallenger.Proof memory proof = IBoltChallenger.Proof({
            inclusionBlockNumber: inclusionBlockNumber,
            previousBlockHeaderRLP: vm.parseJsonBytes(rawPreviousHeader, ".result"),
            inclusionBlockHeaderRLP: vm.parseJsonBytes(rawInclusionHeader, ".result"),
            accountMerkleProof: _RLPEncodeList(vm.parseJsonBytesArray(ethProof, ".result.accountProof")),
            txMerkleProofs: txProofs,
            txIndexesInBlock: txIndexesInBlock
        });

        // check that the inclusion block transactions root matches the root in the tx proof data.
        bytes32 inclusionTxRoot = boltChallenger._decodeBlockHeaderRLPExt(proof.inclusionBlockHeaderRLP).txRoot;
        assertEq(inclusionTxRoot, vm.parseJsonBytes32(txProof1, ".root"));

        // block hash of https://etherscan.io/block/20817617
        bytes32 trustedPreviousBlockHash = 0xb410d12f92ed268b184c1e6523b7d3fea5fcd0ba3f9bc6c6cb9a7e5b1523d225;

        // Resolve the challenge
        vm.resumeGasMetering();
        vm.prank(resolver);

        vm.expectEmit();
        emit IBoltChallenger.ChallengeDefended(challengeID);

        boltChallenger._resolveExt(challengeID, trustedPreviousBlockHash, proof);
    }

    function testResolveExpiredChallenge() public {
        IBoltChallenger.SignedCommitment[] memory commitments = new IBoltChallenger.SignedCommitment[](1);
        commitments[0] = _parseTestCommitment();

        // Open a challenge with the commitment
        vm.resumeGasMetering();
        vm.prank(challenger);
        boltChallenger.openChallenge{value: 1 ether}(commitments);
        vm.pauseGasMetering();

        // Check the challenge was opened
        IBoltChallenger.Challenge[] memory challenges = boltChallenger.getAllChallenges();
        assertEq(challenges.length, 1);

        // Warp time to make the challenge expire
        vm.warp(block.timestamp + 2 weeks);

        // Try to resolve the challenge
        vm.prank(resolver);

        // Get the challenge
        IBoltChallenger.Challenge memory challenge = boltChallenger.getAllChallenges()[0];

        vm.expectEmit();
        emit IBoltChallenger.ChallengeBreached(challenge.id);

        boltChallenger.resolveExpiredChallenge(challenge.id);
    }

    function testCannotResolveChallengeBeforeExpiration() public {
        IBoltChallenger.SignedCommitment[] memory commitments = new IBoltChallenger.SignedCommitment[](1);
        commitments[0] = _parseTestCommitment();

        // Open a challenge with the commitment
        vm.resumeGasMetering();
        vm.prank(challenger);
        boltChallenger.openChallenge{value: 1 ether}(commitments);
        vm.pauseGasMetering();

        // Check the challenge was opened
        IBoltChallenger.Challenge[] memory challenges = boltChallenger.getAllChallenges();
        assertEq(challenges.length, 1);
        bytes32 id = challenges[0].id;

        // Try to resolve the challenge before it expires
        vm.resumeGasMetering();
        vm.prank(resolver);
        vm.expectRevert(IBoltChallenger.ChallengeNotExpired.selector);
        boltChallenger.resolveExpiredChallenge(id);
        vm.pauseGasMetering();
    }

    // =========== Helper functions ===========

    // Helper to create a test commitment with a recent slot, valid for a recent challenge
    function _createRecentBoltCommitment(
        uint256 blockNumber,
        uint256 id
    ) internal view returns (IBoltChallenger.SignedCommitment memory commitment) {
        // pattern: ./test/testdata/signed_tx_{blockNumber}_{id}.json
        string memory base = "./test/testdata/signed_tx_";
        string memory extension = string.concat(vm.toString(blockNumber), "_", vm.toString(id), ".json");
        string memory path = string.concat(base, extension);
        commitment.signedTx = vm.parseJsonBytes(vm.readFile(path), ".raw");

        // pick a recent slot, 100 slots behind the current slot
        commitment.slot = uint64(boltChallenger._getCurrentSlotExt() - 100);

        // sign the new commitment with the target's private key
        bytes32 commitmentID = _computeCommitmentID(commitment.signedTx, commitment.slot);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(targetPK, commitmentID);
        commitment.signature = abi.encodePacked(r, s, v);

        // Normalize v to 27 or 28
        if (uint8(commitment.signature[64]) < 27) {
            commitment.signature[64] = bytes1(uint8(commitment.signature[64]) + 0x1B);
        }

        // Sanity check
        assertEq(ECDSA.recover(commitmentID, commitment.signature), target);

        return commitment;
    }

    // Helper to parse the test commitment from a file
    function _parseTestCommitment() internal view returns (IBoltChallenger.SignedCommitment memory) {
        string memory file = vm.readFile("./test/testdata/bolt_commitment.json");
        IBoltChallenger.SignedCommitment memory commitment = IBoltChallenger.SignedCommitment({
            slot: uint64(vm.parseJsonUint(file, ".slot")),
            signature: vm.parseJsonBytes(file, ".signature"),
            signedTx: vm.parseJsonBytes(file, ".tx")
        });

        // Normalize v to 27 or 28
        if (uint8(commitment.signature[64]) < 27) {
            commitment.signature[64] = bytes1(uint8(commitment.signature[64]) + 0x1B);
        }

        return commitment;
    }

    // Helper to compute the commitment ID
    function _computeCommitmentID(bytes memory signedTx, uint64 slot) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(signedTx), _toLittleEndian(slot)));
    }

    // Helper to encode a list of bytes[] into an RLP list with each item RLP-encoded
    function _RLPEncodeList(
        bytes[] memory _items
    ) internal pure returns (bytes memory) {
        bytes[] memory encodedItems = new bytes[](_items.length);
        for (uint256 i = 0; i < _items.length; i++) {
            encodedItems[i] = RLPWriter.writeBytes(_items[i]);
        }
        return RLPWriter.writeList(encodedItems);
    }

    // Helper to convert a u64 to a little-endian bytes
    function _toLittleEndian(
        uint64 x
    ) internal pure returns (bytes memory) {
        bytes memory b = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            b[i] = bytes1(uint8(x >> (8 * i)));
        }
        return b;
    }
}
