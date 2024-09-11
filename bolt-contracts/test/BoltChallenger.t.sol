// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {BoltChallenger} from "../src/contracts/BoltChallenger.sol";
import {RLPReader} from "../src/lib/rlp/RLPReader.sol";
import {RLPWriter} from "../src/lib/rlp/RLPWriter.sol";
import {SecureMerkleTrie} from "../src/lib/trie/SecureMerkleTrie.sol";

contract BoltChallengerTest is Test {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    BoltChallenger boltChallenger;

    address challenger = makeAddr("challenger");
    address resolver = makeAddr("resolver");

    function setUp() public {
        boltChallenger = new BoltChallenger();
    }

    function testProveHeaderData() public view {
        // Note: In prod, how we obtain the trusted block hash would depend on the context.
        // for recent blocks, we can simply use the blockhash function in the EVM.
        bytes32 trustedBlockHash = 0x531b257cc7ecda14d12007aae5f45924789ea70ab20e3e28d67025028fed61a9;

        // Read the RLP-encoded block header from a file (obtained via `debug_getRawHeader` RPC call)
        bytes memory headerRLP = vm.parseBytes(vm.readFile("./test/testdata/header_rlp.hex"));

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

        assertEq(stateRoot, 0x5e9f1c386d2c33a9bc1a0c09b506cf1610833e986a0f4c6b5e6419691a54ee5c);
        assertEq(transactionsRoot, 0x3d513346b4f4f7de4017e9f0775fe7b20a8eb83115d1d6924327d8d34a1e0a53);
        assertEq(blockNumber, 20_720_835);
        assertEq(gasLimit, 30_000_000);
        assertEq(gasUsed, 19_509_421);
        assertEq(timestamp, 1_725_978_863);
        assertEq(baseFee, 6_353_104_009);
    }

    function testProveAccountData() public view {
        // The account we want to prove
        address accountToProve = 0x0D9f5045B604bA0c050b5eb06D0b25d01c525Ea5;

        // Note: in prod the state root should be obtained from the block header proof.
        // this way we can trust it comes from the right block number. This comes from Mainnet block 20_720_835.
        bytes32 stateRootAtBlock = 0x5e9f1c386d2c33a9bc1a0c09b506cf1610833e986a0f4c6b5e6419691a54ee5c;

        // Read the RLP-encoded account proof from a file. This is obtained from the `eth_getProof`
        // RPC call + ABI-encoding of the resulting accountProof array.
        bytes memory accountProofJson = vm.parseJson(vm.readFile("./test/testdata/eth_proof.json"), ".result.accountProof");
        bytes[] memory accountProofJsonArray = abi.decode(accountProofJson, (bytes[]));
        bytes[] memory accountProofJsonArrayEncoded = new bytes[](accountProofJsonArray.length);
        for (uint i = 0; i < accountProofJsonArray.length; i++) {
            accountProofJsonArrayEncoded[i] = RLPWriter.writeBytes(accountProofJsonArray[i]);
        }
        bytes memory accountProof = RLPWriter.writeList(accountProofJsonArrayEncoded);

        // sanity check
        RLPReader.RLPItem[] memory nodes = RLPReader.readList(accountProof);
        for (uint i = 0; i < nodes.length; i++) {
            // This will fail if the proof is encoded incorrectly
            RLPReader.readBytes(nodes[i]);
        }

        // TODO: debug why the root hash is failing to match
        console.log("before trie.get");
        (bool exists, bytes memory accountRLP) =
            SecureMerkleTrie.get(abi.encodePacked(accountToProve), accountProof, stateRootAtBlock);
        console.log("after trie.get");
        assertEq(exists, true);

        console.logBytes(accountRLP);

        // decode the account RLP into nonce and balance
        RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();
        uint256 nonce = accountFields[0].readUint256();
        uint256 balance = accountFields[1].readUint256();

        console.log(nonce);
        console.log(balance);
    }

    function testProveTransactionInclusion() public view {
        bytes32 txRootAtBlock = 0x3d513346b4f4f7de4017e9f0775fe7b20a8eb83115d1d6924327d8d34a1e0a53;
        bytes32 txHash = 0xdf15fd0565b9f0519259aaf6fef098189c21739ccdf05c31d5a6e13fd9acb669;
        uint256 txIndex = 149;

        // TODO: fix
        // bytes memory txProofJson = vm.parseJson(vm.readFile("./test/testdata/tx_mpt_proof.json"), ".proof");
        // bytes[] memory txProofJsonArray = abi.decode(txProofJson, (bytes[]));
        // bytes[] memory txProofJsonArrayEncoded = new bytes[](txProofJsonArray.length);
        // for (uint i = 0; i < txProofJsonArray.length; i++) {
        //     txProofJsonArrayEncoded[i] = RLPWriter.writeBytes(txProofJsonArray[i]);
        // }
        // bytes memory txProof = RLPWriter.writeList(txProofJsonArrayEncoded);

        // (bool exists, bytes memory transactionRLP) = 
        //     SecureMerkleTrie.get(abi.encodePacked(txHash), txProof, txRootAtBlock);
        // assertEq(exists, true);
    }
}
