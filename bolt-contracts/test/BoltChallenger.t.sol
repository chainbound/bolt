// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {BoltChallenger} from "../src/contracts/BoltChallenger.sol";
import {RLPReader} from "../src/lib/rlp/RLPReader.sol";
import {RLPWriter} from "../src/lib/rlp/RLPWriter.sol";
import {BytesUtils} from "../src/lib/BytesUtils.sol";
import {SecureMerkleTrie} from "../src/lib/trie/SecureMerkleTrie.sol";
import {MerkleTrie} from "../src/lib/trie/MerkleTrie.sol";

contract BoltChallengerTest is Test {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using BytesUtils for bytes;

    BoltChallenger boltChallenger;

    address challenger = makeAddr("challenger");
    address resolver = makeAddr("resolver");

    function setUp() public {
        boltChallenger = new BoltChallenger();
    }

    function testProveHeaderData() public view {
        // Note: In prod, how we obtain the trusted block hash would depend on the context.
        // For recent blocks, we can simply use the blockhash function in the EVM.
        bytes32 trustedBlockHash = 0xba212beac090306b5edea79b5f5cd4c91a0c1568acc489983e2545c48c1a0f42;

        // Read the RLP-encoded block header from a file (obtained via `debug_getRawHeader` RPC call)
        string memory file = vm.readFile("./test/testdata/raw_header.json");
        bytes memory headerRLP = vm.parseJsonBytes(file, ".result");

        assertEq(keccak256(headerRLP), trustedBlockHash);

        // RLP decode the header
        // https://github.com/ethereum/go-ethereum/blob/master/core/types/block.go
        RLPReader.RLPItem[] memory headerFields = headerRLP.toRLPItem().readList();
        bytes32 stateRoot = headerFields[3].readBytes32();
        bytes32 transactionsRoot = headerFields[4].readBytes32();
        uint256 blockNumber = headerFields[8].readUint256();
        uint256 gasLimit = headerFields[9].readUint256();
        uint256 gasUsed = headerFields[10].readUint256();
        uint256 timestamp = headerFields[11].readUint256();
        uint256 baseFee = headerFields[15].readUint256();

        assertEq(stateRoot, 0xebfa3f5945e5d03bb94edf276ee36ca9ce56382686d16acb2e21f7ca6e58d712);
        assertEq(transactionsRoot, 0xeea3c72aa7598c0b741dca81b196cdeaac3d503441fa3620e12eec924ba35c2b);
        assertEq(blockNumber, 20_728_344);
        assertEq(gasLimit, 30_000_000);
        assertEq(gasUsed, 9_503_925);
        assertEq(timestamp, 1_726_069_463);
        assertEq(baseFee, 5_703_406_196);
    }

    function testProveAccountData() public view {
        // The account we want to prove
        address accountToProve = 0x0D9f5045B604bA0c050b5eb06D0b25d01c525Ea5;

        // Note: in prod the state root should be obtained from the block header proof.
        // this way we can trust it comes from the right block number. This comes from Mainnet block 20_728_344.
        bytes32 stateRootAtBlock = 0xebfa3f5945e5d03bb94edf276ee36ca9ce56382686d16acb2e21f7ca6e58d712;

        // Read the RLP-encoded account proof from a file. This is obtained from the `eth_getProof`
        // RPC call + ABI-encoding of the resulting accountProof array.
        string memory file = vm.readFile("./test/testdata/eth_proof.json");
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

        (bool exists, bytes memory accountRLP) =
            SecureMerkleTrie.get(abi.encodePacked(accountToProve), accountProof, stateRootAtBlock);
        assertEq(exists, true);

        // decode the account RLP into nonce and balance
        RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();
        uint256 nonce = accountFields[0].readUint256();
        uint256 balance = accountFields[1].readUint256();

        assertEq(nonce, 234);
        assertEq(balance, 22_281_420_828_500_997);
    }

    function testProveTransactionInclusion() public view {
        // The transaction we want to prove inclusion of
        bytes32 txHash = 0xec9cbdb7ca9cc97542ba6f68b70543e89b701c438d50af827781248e37e06246;

        // MPT proof, obtained with the `eth-trie-proof` CLI tool
        string memory file = vm.readFile("./test/testdata/tx_mpt_proof.json");
        bytes[] memory txProofJson = vm.parseJsonBytesArray(file, ".proof");
        bytes memory txProof = _RLPEncodeList(txProofJson);

        // The transactions root and index in the block, also included in the CLI response
        bytes32 txRootAtBlock = vm.parseJsonBytes32(file, ".root");
        uint256 txIndexInBlock = vm.parseJsonUint(file, ".index");

        bytes memory key = RLPWriter.writeUint(txIndexInBlock);

        // Gotcha: SecureMerkleTrie.get expects the key to be hashed with keccak256
        // but the transaction trie skips this step and uses the raw index as the key.
        (bool exists, bytes memory transactionRLP) = MerkleTrie.get(key, txProof, txRootAtBlock);

        assertEq(exists, true);
        assertEq(keccak256(transactionRLP), txHash);

        // First, we remove the Tx-type byte from the EIP-2718 envelope,
        // then decode the transaction RLP into its fields.
        bytes memory txEip1559 = transactionRLP.slice(1, transactionRLP.length - 1);
        RLPReader.RLPItem[] memory txFields = txEip1559.toRLPItem().readList();
        uint256 chainId = txFields[0].readUint256();
        uint256 nonce = txFields[1].readUint256();
        uint256 maxPriorityFeePerGas = txFields[2].readUint256();
        uint256 maxFeePerGas = txFields[3].readUint256();
        uint256 gasLimit = txFields[4].readUint256();
        address to = txFields[5].readAddress();
        uint256 value = txFields[6].readUint256();
        bytes memory data = txFields[7].readBytes();

        assertEq(chainId, 1);
        assertEq(nonce, 4);
        assertEq(maxPriorityFeePerGas, 1_329_961_284);
        assertEq(maxFeePerGas, 8_696_356_057);
        assertEq(gasLimit, 21_000);
        assertEq(to, 0x45562Ea400fFD5FaEfeefD0336681852D214d5a5);
        assertEq(value, 1_817_357_890_317_030);
        assertEq(data.length, 0);
    }

    // Helper function to encode a list of bytes[] into an RLP list with each item RLP-encoded
    function _RLPEncodeList(
        bytes[] memory _items
    ) internal pure returns (bytes memory) {
        bytes[] memory encodedItems = new bytes[](_items.length);
        for (uint256 i = 0; i < _items.length; i++) {
            encodedItems[i] = RLPWriter.writeBytes(_items[i]);
        }
        return RLPWriter.writeList(encodedItems);
    }
}
