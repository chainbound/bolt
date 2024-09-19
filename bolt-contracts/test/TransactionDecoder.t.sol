// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {TransactionDecoder} from "../src/lib/TransactionDecoder.sol";
import {BytesUtils} from "../src/lib/BytesUtils.sol";

// We use a contract to expose internal library functions
contract DecoderImpl {
    function decodeEnveloped(
        bytes memory raw
    ) public pure returns (TransactionDecoder.Transaction memory) {
        return TransactionDecoder.decodeEnveloped(raw);
    }

    function preimage(
        TransactionDecoder.Transaction memory transaction
    ) public pure returns (bytes32) {
        return TransactionDecoder.preimage(transaction);
    }

    function signature(
        TransactionDecoder.Transaction memory transaction
    ) public pure returns (bytes memory) {
        return TransactionDecoder.signature(transaction);
    }
}

contract TransactionDecoderTest is Test {
    using TransactionDecoder for TransactionDecoder.Transaction;

    DecoderImpl decoder;

    struct TestCase {
        string name;
        uint256 privateKey;
        bytes unsignedLegacy;
        bytes unsignedEip155;
        bytes unsignedBerlin;
        bytes unsignedLondon;
        bytes unsignedCancun;
        bytes signedLegacy;
        bytes signedEip155;
        bytes signedBerlin;
        bytes signedLondon;
        bytes signedCancun;
        TransactionDecoder.Transaction transaction;
    }

    function setUp() public {
        decoder = new DecoderImpl();
    }

    function testDecodeAllTestCases() public {
        uint256 i = 0;
        while (true) {
            string memory path = _getTestCasePath(i);
            if (!vm.isFile(path)) break;

            // Cycle through all test cases and run them one by one
            _decodeTestCase(i);
            i++;
        }
    }

    function _decodeTestCase(
        uint256 id
    ) internal view {
        TestCase memory testCase = _readTestCase(id);

        // Type 0 pre eip-155 (with chainId = 0)
        TransactionDecoder.Transaction memory decodedSignedLegacy = decoder.decodeEnveloped(testCase.signedLegacy);
        _assertTransaction(TransactionDecoder.TxType.Legacy, decodedSignedLegacy, testCase.transaction, false);
        assertEq(decodedSignedLegacy.unsigned(), testCase.unsignedLegacy);
        assertEq(decodedSignedLegacy.recoverSender(), vm.addr(testCase.privateKey));

        // Type 0 post eip-155 (with optional legacy chainId)
        TransactionDecoder.Transaction memory decodedSignedEip155 = decoder.decodeEnveloped(testCase.signedEip155);
        _assertTransaction(TransactionDecoder.TxType.Legacy, decodedSignedEip155, testCase.transaction, true);
        assertEq(decodedSignedEip155.unsigned(), testCase.unsignedEip155);
        assertEq(decodedSignedEip155.recoverSender(), vm.addr(testCase.privateKey));

        // Type 1 with optional access list
        TransactionDecoder.Transaction memory decodedSignedBerlin = decoder.decodeEnveloped(testCase.signedBerlin);
        _assertTransaction(TransactionDecoder.TxType.Eip2930, decodedSignedBerlin, testCase.transaction, true);
        assertEq(decodedSignedBerlin.unsigned(), testCase.unsignedBerlin);
        assertEq(decodedSignedBerlin.recoverSender(), vm.addr(testCase.privateKey));

        // Type 2 with fee market fields
        TransactionDecoder.Transaction memory decodedSignedLondon = decoder.decodeEnveloped(testCase.signedLondon);
        _assertTransaction(TransactionDecoder.TxType.Eip1559, decodedSignedLondon, testCase.transaction, true);
        assertEq(decodedSignedLondon.unsigned(), testCase.unsignedLondon);
        assertEq(decodedSignedLondon.recoverSender(), vm.addr(testCase.privateKey));

        // Type 3 with blob fields
        TransactionDecoder.Transaction memory decodedSignedCancun = decoder.decodeEnveloped(testCase.signedCancun);
        _assertTransaction(TransactionDecoder.TxType.Eip4844, decodedSignedCancun, testCase.transaction, true);
        assertEq(decodedSignedCancun.unsigned(), testCase.unsignedCancun);
        assertEq(decodedSignedCancun.recoverSender(), vm.addr(testCase.privateKey));
    }

    // Helper to get the path of a test case file based on its index
    function _getTestCasePath(
        uint256 id
    ) internal pure returns (string memory) {
        // Location of the test cases on disk (relative to the project root)
        // Example: ./test/testdata/transactions/random_10.json
        return string.concat("./test/testdata/transactions/random_", vm.toString(id), ".json");
    }

    function _assertTransaction(
        TransactionDecoder.TxType txType,
        TransactionDecoder.Transaction memory decoded,
        TransactionDecoder.Transaction memory expected,
        bool isEip155
    ) internal pure {
        assertEq(uint8(decoded.txType), uint8(txType));

        if (!isEip155) {
            // Pre-EIP-155 transactions have a chainId of 0
            assertEq(decoded.chainId, 0);
        } else {
            assertEq(decoded.chainId, expected.chainId);
        }

        assertEq(decoded.data, expected.data);
        assertEq(decoded.gasLimit, expected.gasLimit);
        assertEq(decoded.nonce, expected.nonce);
        assertEq(decoded.to, expected.to);
        assertEq(decoded.value, expected.value);

        if (uint8(txType) < 2) {
            assertEq(decoded.gasPrice, expected.gasPrice);
        }

        if (uint8(txType) >= 1) {
            // We keep access lists as opaque bytes for now, because we simply re-encode
            // them to obtain the unsigned transaction. So we can't compare them directly.
            // assertEq(decoded.accessList, expected.accessList);
        }

        if (uint8(txType) >= 2) {
            assertEq(decoded.maxFeePerGas, expected.maxFeePerGas);
            assertEq(decoded.maxPriorityFeePerGas, expected.maxPriorityFeePerGas);
        }

        if (uint8(txType) == 3) {
            assertEq(decoded.maxFeePerBlobGas, expected.maxFeePerBlobGas);
            assertEq(decoded.blobVersionedHashes.length, expected.blobVersionedHashes.length);
            for (uint256 i = 0; i < decoded.blobVersionedHashes.length; i++) {
                assertEq(decoded.blobVersionedHashes[i], expected.blobVersionedHashes[i]);
            }
        }
    }

    function _readTestCase(
        uint256 id
    ) public view returns (TestCase memory) {
        string memory file = vm.readFile(_getTestCasePath(id));

        TransactionDecoder.Transaction memory transaction = TransactionDecoder.Transaction({
            chainId: uint64(_parseUintFromBytes(vm.parseJsonBytes(file, ".transaction.chainId"))),
            data: vm.parseJsonBytes(file, ".transaction.data"),
            gasLimit: _parseUintFromBytes(vm.parseJsonBytes(file, ".transaction.gasLimit")),
            gasPrice: _parseUintFromBytes(vm.parseJsonBytes(file, ".transaction.gasPrice")),
            maxFeePerGas: _parseUintFromBytes(vm.parseJsonBytes(file, ".transaction.maxFeePerGas")),
            maxPriorityFeePerGas: _parseUintFromBytes(vm.parseJsonBytes(file, ".transaction.maxPriorityFeePerGas")),
            nonce: vm.parseJsonUint(file, ".transaction.nonce"),
            to: vm.parseJsonAddress(file, ".transaction.to"),
            value: _parseUintFromBytes(vm.parseJsonBytes(file, ".transaction.value")),
            maxFeePerBlobGas: _parseUintFromBytes(vm.parseJsonBytes(file, ".transaction.maxFeePerBlobGas")),
            blobVersionedHashes: vm.parseJsonBytes32Array(file, ".transaction.blobVersionedHashes"),
            // Note: These fields aren't present in the test cases so they can be skipped.
            // These are tested indirectly by the signature and preimage checks.
            txType: TransactionDecoder.TxType.Legacy,
            accessList: new bytes[](0),
            // Signature is checked by recovering the sender and comparing it to the pubkey
            // derived from the private key in the test case.
            sig: "",
            // Note: these fields are just internal helpers for the decoder library.
            legacyV: 0,
            isChainIdSet: false
        });

        return TestCase({
            name: vm.parseJsonString(file, ".name"),
            privateKey: uint256(vm.parseJsonBytes32(file, ".privateKey")),
            unsignedLegacy: vm.parseJsonBytes(file, ".unsignedLegacy"),
            unsignedEip155: vm.parseJsonBytes(file, ".unsignedEip155"),
            unsignedBerlin: vm.parseJsonBytes(file, ".unsignedBerlin"),
            unsignedLondon: vm.parseJsonBytes(file, ".unsignedLondon"),
            unsignedCancun: vm.parseJsonBytes(file, ".unsignedCancun"),
            signedLegacy: vm.parseJsonBytes(file, ".signedLegacy"),
            signedEip155: vm.parseJsonBytes(file, ".signedEip155"),
            signedBerlin: vm.parseJsonBytes(file, ".signedBerlin"),
            signedLondon: vm.parseJsonBytes(file, ".signedLondon"),
            signedCancun: vm.parseJsonBytes(file, ".signedCancun"),
            transaction: transaction
        });
    }

    // Helper to parse an uint from bytes padded to the left
    function _parseUintFromBytes(
        bytes memory data
    ) internal pure returns (uint256) {
        return uint256(BytesUtils.toBytes32PadLeft(data));
    }

    function _parseOpaqueAccessList(
        bytes memory data
    ) internal pure returns (bytes[] memory) {}
}
