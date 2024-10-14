// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {RLPReader} from "./rlp/RLPReader.sol";
import {RLPWriter} from "./rlp/RLPWriter.sol";
import {BytesUtils} from "./BytesUtils.sol";

/// @title TransactionDecoder
/// @notice A library to decode Ethereum transactions in EIP-2718 format
/// into a structured transaction object, and to recover the sender.
library TransactionDecoder {
    using BytesUtils for bytes;
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    /// @notice The type of transaction
    enum TxType {
        Legacy,
        Eip2930,
        Eip1559,
        Eip4844
    }

    /// @notice A decoded transaction object
    struct Transaction {
        TxType txType;
        uint64 chainId;
        // As Solidity doesn't have NULL values, we use this flag to differentiate between
        // an explicit chainId of 0 and a missing chainID. The difference is important for
        // encoding unsigned eip-155 legacy transactions.
        bool isChainIdSet;
        uint256 nonce;
        uint256 gasPrice;
        uint256 maxPriorityFeePerGas;
        uint256 maxFeePerGas;
        uint256 gasLimit;
        address to;
        uint256 value;
        bytes data;
        bytes[] accessList;
        uint256 maxFeePerBlobGas;
        bytes32[] blobVersionedHashes;
        bytes sig;
        uint64 legacyV;
    }

    error NoSignature();
    error InvalidYParity();
    error UnsupportedTxType();
    error InvalidFieldCount();
    error InvalidSignatureLength();

    /// @notice Decode a raw transaction into a transaction object
    /// @param raw The raw transaction bytes
    /// @return transaction The decoded transaction object
    function decodeEnveloped(
        bytes memory raw
    ) internal pure returns (Transaction memory transaction) {
        bytes1 prefix = raw[0];

        if (prefix >= 0x7F) {
            return _decodeLegacy(raw);
        } else if (prefix == 0x01) {
            return _decodeEip2930(raw);
        } else if (prefix == 0x02) {
            return _decodeEip1559(raw);
        } else if (prefix == 0x03) {
            return _decodeEip4844(raw);
        } else {
            revert UnsupportedTxType();
        }
    }

    /// @notice Recover the sender of a transaction
    /// @param transaction The transaction object
    /// @return sender The address of the sender
    function recoverSender(
        Transaction memory transaction
    ) internal pure returns (address) {
        return ECDSA.recover(preimage(transaction), signature(transaction));
    }

    /// @notice Compute the preimage of a transaction object
    /// @dev This is the hash of the transaction that is signed by the sender to obtain the signature
    /// @param transaction The transaction object
    /// @return preimg The preimage hash of the transaction
    function preimage(
        Transaction memory transaction
    ) internal pure returns (bytes32 preimg) {
        preimg = keccak256(unsigned(transaction));
    }

    /// @notice Compute the unsigned transaction object
    /// @dev This is the transaction object without the signature
    /// @param transaction The transaction object
    /// @return unsignedTx The unsigned transaction object
    function unsigned(
        Transaction memory transaction
    ) internal pure returns (bytes memory unsignedTx) {
        if (transaction.txType == TxType.Legacy) {
            unsignedTx = _unsignedLegacy(transaction);
        } else if (transaction.txType == TxType.Eip2930) {
            unsignedTx = _unsignedEip2930(transaction);
        } else if (transaction.txType == TxType.Eip1559) {
            unsignedTx = _unsignedEip1559(transaction);
        } else if (transaction.txType == TxType.Eip4844) {
            unsignedTx = _unsignedEip4844(transaction);
        } else {
            revert UnsupportedTxType();
        }
    }

    /// @notice Return the hex-encoded signature of a transaction object
    /// @param transaction The transaction object
    /// @return sig The hex-encoded signature
    function signature(
        Transaction memory transaction
    ) internal pure returns (bytes memory sig) {
        if (transaction.sig.length == 0) {
            revert NoSignature();
        } else if (transaction.sig.length != 65) {
            revert InvalidSignatureLength();
        } else {
            sig = transaction.sig;
        }
    }

    /// @notice Helper to decode a legacy (type 0) transaction
    /// @param raw The raw transaction bytes
    /// @return transaction The decoded transaction object
    function _decodeLegacy(
        bytes memory raw
    ) private pure returns (Transaction memory transaction) {
        transaction.txType = TxType.Legacy;

        // Legacy transactions don't have a type prefix, so we can decode directly
        RLPReader.RLPItem[] memory fields = raw.toRLPItem().readList();

        if (fields.length != 9 && fields.length != 6) {
            revert InvalidFieldCount();
        }

        transaction.nonce = fields[0].readUint256();
        transaction.gasPrice = fields[1].readUint256();
        transaction.gasLimit = fields[2].readUint256();
        transaction.to = fields[3].readAddress();
        transaction.value = fields[4].readUint256();
        transaction.data = fields[5].readBytes();

        // Legacy unsigned transaction
        if (fields.length == 6) {
            return transaction;
        }

        // rlp expects signature values in (v, r, s) order
        uint64 v = uint64(fields[6].readUint256());
        uint256 r = fields[7].readUint256();
        uint256 s = fields[8].readUint256();

        if (r == 0 && s == 0) {
            // EIP-155 unsigned transaction
            transaction.chainId = v;
            transaction.isChainIdSet = true;
        } else {
            if (v >= 35) {
                // Compute the EIP-155 chain ID (or 0 for legacy)
                transaction.chainId = (v - 35) / 2;
                transaction.legacyV = v;
                transaction.isChainIdSet = true;
            }

            // Compute the signature
            uint8 parityV = uint8(((v ^ 1) % 2) + 27);
            transaction.sig = abi.encodePacked(bytes32(r), bytes32(s), parityV);
        }
    }

    /// @notice Helper to decode an EIP-2930 (type 1) transaction
    /// @param raw The raw transaction bytes
    /// @return transaction The decoded transaction object
    function _decodeEip2930(
        bytes memory raw
    ) private pure returns (Transaction memory transaction) {
        transaction.txType = TxType.Eip2930;

        // Skip the first byte (transaction type)
        bytes memory rlpData = raw.slice(1, raw.length - 1);
        RLPReader.RLPItem[] memory fields = rlpData.toRLPItem().readList();

        if (fields.length != 8 && fields.length != 11) {
            revert InvalidFieldCount();
        }

        transaction.chainId = uint64(fields[0].readUint256());
        transaction.nonce = fields[1].readUint256();
        transaction.gasPrice = fields[2].readUint256();
        transaction.gasLimit = fields[3].readUint256();
        transaction.to = fields[4].readAddress();
        transaction.value = fields[5].readUint256();
        transaction.data = fields[6].readBytes();

        RLPReader.RLPItem[] memory accessListItems = fields[7].readList();
        transaction.accessList = new bytes[](accessListItems.length);
        for (uint256 i = 0; i < accessListItems.length; i++) {
            transaction.accessList[i] = accessListItems[i].readRawBytes();
        }

        // EIP-2930 Unsigned transaction
        if (fields.length == 8) {
            return transaction;
        }

        uint8 v = uint8(fields[8].readUint256()) + 27;
        bytes32 r = fields[9].readBytes32();
        bytes32 s = fields[10].readBytes32();

        // compute the signature
        transaction.sig = abi.encodePacked(r, s, v);
    }

    /// @notice Helper to decode an EIP-1559 (type 2) transaction
    /// @param raw The raw transaction bytes
    /// @return transaction The decoded transaction object
    function _decodeEip1559(
        bytes memory raw
    ) private pure returns (Transaction memory transaction) {
        transaction.txType = TxType.Eip1559;

        // Skip the first byte (transaction type)
        bytes memory rlpData = raw.slice(1, raw.length - 1);
        RLPReader.RLPItem[] memory fields = rlpData.toRLPItem().readList();

        if (fields.length != 9 && fields.length != 12) {
            revert InvalidFieldCount();
        }

        transaction.chainId = uint64(fields[0].readUint256());
        transaction.nonce = fields[1].readUint256();
        transaction.maxPriorityFeePerGas = fields[2].readUint256();
        transaction.maxFeePerGas = fields[3].readUint256();
        transaction.gasLimit = fields[4].readUint256();
        transaction.to = fields[5].readAddress();
        transaction.value = fields[6].readUint256();
        transaction.data = fields[7].readBytes();

        RLPReader.RLPItem[] memory accessListItems = fields[8].readList();
        transaction.accessList = new bytes[](accessListItems.length);
        for (uint256 i = 0; i < accessListItems.length; i++) {
            transaction.accessList[i] = accessListItems[i].readRawBytes();
        }

        if (fields.length == 9) {
            // EIP-1559 Unsigned transaction
            return transaction;
        }

        uint8 v = uint8(fields[9].readUint256()) + 27;
        bytes32 r = fields[10].readBytes32();
        bytes32 s = fields[11].readBytes32();

        // compute the signature
        transaction.sig = abi.encodePacked(r, s, v);
    }

    /// @notice Helper to decode an EIP-4844 (type 3) transaction
    /// @param raw The raw transaction bytes
    /// @return transaction The decoded transaction object
    function _decodeEip4844(
        bytes memory raw
    ) private pure returns (Transaction memory transaction) {
        transaction.txType = TxType.Eip4844;

        // Skip the first byte (transaction type)
        bytes memory rlpData = raw.slice(1, raw.length - 1);
        RLPReader.RLPItem[] memory fields = rlpData.toRLPItem().readList();

        if (fields.length != 11 && fields.length != 14) {
            revert InvalidFieldCount();
        }

        transaction.chainId = uint64(fields[0].readUint256());
        transaction.nonce = fields[1].readUint256();
        transaction.maxPriorityFeePerGas = fields[2].readUint256();
        transaction.maxFeePerGas = fields[3].readUint256();
        transaction.gasLimit = fields[4].readUint256();
        transaction.to = fields[5].readAddress();
        transaction.value = fields[6].readUint256();
        transaction.data = fields[7].readBytes();

        RLPReader.RLPItem[] memory accessListItems = fields[8].readList();
        transaction.accessList = new bytes[](accessListItems.length);
        for (uint256 i = 0; i < accessListItems.length; i++) {
            transaction.accessList[i] = accessListItems[i].readRawBytes();
        }

        transaction.maxFeePerBlobGas = fields[9].readUint256();

        RLPReader.RLPItem[] memory blobVersionedHashesItems = fields[10].readList();
        transaction.blobVersionedHashes = new bytes32[](blobVersionedHashesItems.length);
        for (uint256 i = 0; i < blobVersionedHashesItems.length; i++) {
            transaction.blobVersionedHashes[i] = blobVersionedHashesItems[i].readBytes32();
        }

        if (fields.length == 11) {
            // Unsigned transaction
            return transaction;
        }

        uint8 v = uint8(fields[11].readUint256()) + 27;
        bytes32 r = fields[12].readBytes32();
        bytes32 s = fields[13].readBytes32();

        // compute the signature
        transaction.sig = abi.encodePacked(r, s, v);
    }

    /// @notice Helper to RLP-encode an unsigned legacy transaction
    /// @param transaction The transaction object
    /// @return unsignedTx The unsigned transaction bytes
    function _unsignedLegacy(
        Transaction memory transaction
    ) private pure returns (bytes memory unsignedTx) {
        uint64 chainId = 0;
        if (transaction.chainId != 0) {
            // A chainId was provided: if non-zero, we'll use EIP-155
            chainId = transaction.chainId;
        } else if (transaction.sig.length != 0) {
            // No explicit chainId, but EIP-155 have a derived implicit chainId
            // based on the V value of the signature
            if (transaction.legacyV >= 35) {
                chainId = (transaction.legacyV - 35) / 2;
            }
        }

        uint256 fieldsCount = 6 + (transaction.isChainIdSet ? 3 : 0);
        bytes[] memory fields = new bytes[](fieldsCount);

        fields[0] = RLPWriter.writeUint(transaction.nonce);
        fields[1] = RLPWriter.writeUint(transaction.gasPrice);
        fields[2] = RLPWriter.writeUint(transaction.gasLimit);
        fields[3] = RLPWriter.writeAddress(transaction.to);
        fields[4] = RLPWriter.writeUint(transaction.value);
        fields[5] = RLPWriter.writeBytes(transaction.data);

        if (transaction.isChainIdSet) {
            if (transaction.chainId == 0) {
                // Edge case: chainId is 0, but we still need to encode it
                // as a single empty byte.
                fields[6] = abi.encodePacked(bytes1(0));
            } else {
                fields[6] = RLPWriter.writeUint(chainId);
            }

            fields[7] = RLPWriter.writeBytes(new bytes(0));
            fields[8] = RLPWriter.writeBytes(new bytes(0));
        }

        unsignedTx = RLPWriter.writeList(fields);
    }

    /// @notice Helper to RLP-encode an unsigned EIP-2930 transaction
    /// @param transaction The transaction object
    /// @return unsignedTx The unsigned transaction bytes
    function _unsignedEip2930(
        Transaction memory transaction
    ) private pure returns (bytes memory unsignedTx) {
        bytes[] memory fields = new bytes[](8);

        fields[0] = RLPWriter.writeUint(transaction.chainId);
        fields[1] = RLPWriter.writeUint(transaction.nonce);
        fields[2] = RLPWriter.writeUint(transaction.gasPrice);
        fields[3] = RLPWriter.writeUint(transaction.gasLimit);
        fields[4] = RLPWriter.writeAddress(transaction.to);
        fields[5] = RLPWriter.writeUint(transaction.value);
        fields[6] = RLPWriter.writeBytes(transaction.data);

        bytes[] memory accessList = new bytes[](transaction.accessList.length);
        for (uint256 i = 0; i < transaction.accessList.length; i++) {
            accessList[i] = transaction.accessList[i];
        }
        fields[7] = RLPWriter.writeList(accessList);

        // EIP-2718 envelope
        unsignedTx = abi.encodePacked(uint8(TxType.Eip2930), RLPWriter.writeList(fields));
    }

    /// @notice Helper to RLP-encode an unsigned EIP-1559 transaction
    /// @param transaction The transaction object
    /// @return unsignedTx The unsigned transaction bytes
    function _unsignedEip1559(
        Transaction memory transaction
    ) private pure returns (bytes memory unsignedTx) {
        bytes[] memory fields = new bytes[](9);

        fields[0] = RLPWriter.writeUint(transaction.chainId);
        fields[1] = RLPWriter.writeUint(transaction.nonce);
        fields[2] = RLPWriter.writeUint(transaction.maxPriorityFeePerGas);
        fields[3] = RLPWriter.writeUint(transaction.maxFeePerGas);
        fields[4] = RLPWriter.writeUint(transaction.gasLimit);
        fields[5] = RLPWriter.writeAddress(transaction.to);
        fields[6] = RLPWriter.writeUint(transaction.value);
        fields[7] = RLPWriter.writeBytes(transaction.data);

        bytes[] memory accessList = new bytes[](transaction.accessList.length);
        for (uint256 i = 0; i < transaction.accessList.length; i++) {
            accessList[i] = transaction.accessList[i];
        }
        fields[8] = RLPWriter.writeList(accessList);

        // EIP-2718 envelope
        unsignedTx = abi.encodePacked(uint8(TxType.Eip1559), RLPWriter.writeList(fields));
    }

    /// @notice Helper to RLP-encode an unsigned EIP-4844 transaction
    /// @param transaction The transaction object
    /// @return unsignedTx The unsigned transaction bytes
    function _unsignedEip4844(
        Transaction memory transaction
    ) private pure returns (bytes memory unsignedTx) {
        bytes[] memory fields = new bytes[](11);

        fields[0] = RLPWriter.writeUint(transaction.chainId);
        fields[1] = RLPWriter.writeUint(transaction.nonce);
        fields[2] = RLPWriter.writeUint(transaction.maxPriorityFeePerGas);
        fields[3] = RLPWriter.writeUint(transaction.maxFeePerGas);
        fields[4] = RLPWriter.writeUint(transaction.gasLimit);
        fields[5] = RLPWriter.writeAddress(transaction.to);
        fields[6] = RLPWriter.writeUint(transaction.value);
        fields[7] = RLPWriter.writeBytes(transaction.data);

        bytes[] memory accessList = new bytes[](transaction.accessList.length);
        for (uint256 i = 0; i < transaction.accessList.length; i++) {
            accessList[i] = transaction.accessList[i];
        }
        fields[8] = RLPWriter.writeList(accessList);

        fields[9] = RLPWriter.writeUint(transaction.maxFeePerBlobGas);

        bytes[] memory blobVersionedHashes = new bytes[](transaction.blobVersionedHashes.length);
        for (uint256 i = 0; i < transaction.blobVersionedHashes.length; i++) {
            // Decode bytes32 as uint256 (RLPWriter doesn't support bytes32 but they are equivalent)
            blobVersionedHashes[i] = RLPWriter.writeUint(uint256(transaction.blobVersionedHashes[i]));
        }
        fields[10] = RLPWriter.writeList(blobVersionedHashes);

        // EIP-2718 envelope
        unsignedTx = abi.encodePacked(uint8(TxType.Eip4844), RLPWriter.writeList(fields));
    }
}
