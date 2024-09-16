// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {RLPReader} from "./rlp/RLPReader.sol";

library TransactionDecoder {
    error InvalidTransaction();

    struct Transaction {
        uint8 txType;
        uint64 chainId;
        uint64 nonce;
        uint256 gasPrice;
        uint256 maxPriorityFeePerGas;
        uint256 maxFeePerGas;
        uint256 gasLimit;
        address to;
        uint256 value;
        bytes data;
    }

    function decodeRaw(
        bytes memory raw
    ) internal pure returns (Transaction memory tx) {
        // TODO: parse tx depending on the type (0, 1, 2, 3)
    }

    function preimage(
        Transaction memory tx
    ) internal pure returns (bytes32 preimage) {
        preimage = keccak256(unsigned(tx));
    }

    function unsigned(
        Transaction memory tx
    ) internal pure returns (bytes memory unsignedTx) {
        // TODO: implement
    }

    function signature(
        Transaction memory tx
    ) internal pure returns (bytes memory signature) {
        // TODO: implement
    }

    // TODO: implement
    function _decodeTransactionRLP(
        bytes calldata transactionRLP
    ) internal pure returns (TransactionDecoder.Transaction memory transaction) {
        RLPReader.RLPItem[] memory transactionFields = transactionRLP.toRLPItem().readList();

        transaction.nonce = transactionFields[0].readUint256();
        transaction.gasPrice = transactionFields[1].readUint256();
        transaction.gasLimit = transactionFields[2].readUint256();
        // TODO: other fields in TransactionDecoder.Transaction
    }
}
