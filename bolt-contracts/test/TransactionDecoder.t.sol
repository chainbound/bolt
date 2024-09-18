// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {TransactionDecoder} from "../src/lib/TransactionDecoder.sol";
import {BytesUtils} from "../src/lib/BytesUtils.sol";

// Use a contract to expose internal library functions
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

    uint8 constant TEST_CASE_COUNT = 11;

    struct TestCase {
        string name;
        uint256 privateKey;
        bytes unsignedLegacy;
        bytes unsignedEip155;
        bytes unsignedBerlin;
        bytes unsignedLondon;
        bytes signedLegacy;
        bytes signedEip155;
        bytes signedBerlin;
        bytes signedLondon;
        TransactionDecoder.Transaction transaction;
    }

    function setUp() public {
        decoder = new DecoderImpl();
    }

    function testDecodeAllTestCases() public view {
        // Cycle through all test cases and run them one by one
        for (uint8 i = 0; i < TEST_CASE_COUNT; i++) {
            _decodeTestCase(i);
        }
    }

    function _decodeTestCase(
        uint8 id
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
    }

    function _assertTransaction(
        TransactionDecoder.TxType txType,
        TransactionDecoder.Transaction memory decoded,
        TransactionDecoder.Transaction memory expected,
        bool isEip155
    ) internal pure {
        assertEq(uint8(decoded.txType), uint8(txType));

        if (!isEip155) {
            // Note: Pre-EIP-155 transactions have a chainId of 0
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
            // TODO: add support for parsing EIP-2930. This is not strictly needed right now.
            // assertEq(decoded.accessList, expected.accessList);
        }

        if (uint8(txType) >= 2) {
            assertEq(decoded.maxFeePerGas, expected.maxFeePerGas);
            assertEq(decoded.maxPriorityFeePerGas, expected.maxPriorityFeePerGas);
        }
    }

    function _readTestCase(
        uint8 id
    ) public view returns (TestCase memory) {
        string memory base = "./test/testdata/transactions/random_";
        string memory file = vm.readFile(string.concat(base, vm.toString(uint256(id)), ".json"));

        TransactionDecoder.Transaction memory transaction = TransactionDecoder.Transaction({
            chainId: uint64(uint256(vm.parseJsonUint(file, ".transaction.chainId"))),
            data: vm.parseJsonBytes(file, ".transaction.data"),
            gasLimit: _parseUintFromBytes(vm.parseJsonBytes(file, ".transaction.gasLimit")),
            gasPrice: vm.parseJsonUint(file, ".transaction.gasPrice"),
            maxFeePerGas: _parseUintFromBytes(vm.parseJsonBytes(file, ".transaction.maxFeePerGas")),
            maxPriorityFeePerGas: _parseUintFromBytes(vm.parseJsonBytes(file, ".transaction.maxPriorityFeePerGas")),
            nonce: vm.parseJsonUint(file, ".transaction.nonce"),
            to: vm.parseJsonAddress(file, ".transaction.to"),
            value: _parseUintFromBytes(vm.parseJsonBytes(file, ".transaction.value")),
            // Note: These fields aren't used in the test cases so they can be skipped
            txType: TransactionDecoder.TxType.Legacy,
            accessList: new bytes[](0),
            maxFeePerBlobGas: 0, // TODO: add support for EIP-4844
            blobVersionedHashes: new bytes[](0), // TODO: add support for EIP-4844
            sig: "",
            legacyV: 0
        });

        return TestCase({
            name: vm.parseJsonString(file, ".name"),
            privateKey: uint256(vm.parseJsonBytes32(file, ".privateKey")),
            unsignedLegacy: vm.parseJsonBytes(file, ".unsignedLegacy"),
            unsignedEip155: vm.parseJsonBytes(file, ".unsignedEip155"),
            unsignedBerlin: vm.parseJsonBytes(file, ".unsignedBerlin"),
            unsignedLondon: vm.parseJsonBytes(file, ".unsignedLondon"),
            signedLegacy: vm.parseJsonBytes(file, ".signedLegacy"),
            signedEip155: vm.parseJsonBytes(file, ".signedEip155"),
            signedBerlin: vm.parseJsonBytes(file, ".signedBerlin"),
            signedLondon: vm.parseJsonBytes(file, ".signedLondon"),
            transaction: transaction
        });
    }

    function _parseUintFromBytes(
        bytes memory data
    ) internal view returns (uint256) {
        return uint256(BytesUtils.toBytes32PadLeft(data));
    }
}
