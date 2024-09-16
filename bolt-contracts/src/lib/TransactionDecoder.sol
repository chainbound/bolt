// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {RLPReader} from "./rlp/RLPReader.sol";

library TransactionDecoder {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    enum TxType {
        Legacy, // 0
        Eip2930, // 1
        Eip1559, // 2
        Eip4844 // 3

    }

    struct Transaction {
        TxType txType;
        uint256 chainId;
        uint256 nonce;
        uint256 gasPrice;
        uint256 maxPriorityFeePerGas;
        uint256 maxFeePerGas;
        uint256 gasLimit;
        address to;
        uint256 value;
        bytes data;
        bytes accessList;
        bytes sig;
    }

    error UnsupportedTxType();

    function decodeEnveloped(
        bytes memory raw
    ) internal pure returns (Transaction memory transaction) {
        if (raw[0] >= 0x7F) {
            return _decodeLegacy(raw);
        } else if (raw[0] == 0x01) {
            return _decodeEip2930(raw);
        } else if (raw[0] == 0x02) {
            return _decodeEip1559(raw);
        } else if (raw[0] == 0x03) {
            return _decodeEip4844(raw);
        } else {
            revert UnsupportedTxType();
        }
    }

    function decodeRLP(
        bytes memory txRLP
    ) internal pure returns (Transaction memory transaction) {
        // TODO: implement
    }

    function preimage(
        Transaction memory transaction
    ) internal pure returns (bytes32 preimg) {
        preimg = keccak256(unsigned(transaction));
    }

    function unsigned(
        Transaction memory transaction
    ) internal pure returns (bytes memory unsignedTx) {
        if (transaction.txType == TxType.Legacy) {
            unsignedTx = abi.encodePacked(
                transaction.nonce,
                transaction.gasPrice,
                transaction.gasLimit,
                transaction.to, // TODO: what if this is empty?
                transaction.value,
                transaction.data,
                transaction.chainId
            );
        } else if (transaction.txType == TxType.Eip2930) {
            // TODO: implement
        } else if (transaction.txType == TxType.Eip1559) {
            // TODO: implement
        } else if (transaction.txType == TxType.Eip4844) {
            // TODO: implement
        }
    }

    function signature(
        Transaction memory transaction
    ) internal pure returns (bytes memory sig) {
        // TODO: implement
    }

    function _decodeLegacy(
        bytes memory raw
    ) internal pure returns (Transaction memory transaction) {
        RLPReader.RLPItem[] memory fields = raw.toRLPItem().readList();

        transaction.txType = TxType.Legacy;
        transaction.nonce = fields[0].readUint256();
        transaction.gasPrice = fields[1].readUint256();
        transaction.gasLimit = fields[2].readUint256();
        transaction.to = fields[3].readAddress();
        transaction.value = fields[4].readUint256();
        transaction.data = fields[5].readBytes();

        uint256 v = fields[6].readUint256();
        bytes32 r = fields[7].readBytes32();
        bytes32 s = fields[8].readBytes32();

        if (r == 0 && s == 0) {
            transaction.chainId = v;
        } else {
            // Compute the EIP-155 chain ID
            uint256 chainId = 0;
            if (v > 35) {
                chainId = (v - 35) / 2;
            }
            transaction.chainId = chainId;

            // Compute the sig
            transaction.sig = abi.encodePacked(v, r, s);
        }
    }

    function _decodeEip2930(
        bytes memory raw
    ) internal pure returns (Transaction memory transaction) {
        RLPReader.RLPItem[] memory fields = raw.toRLPItem().readList();

        transaction.txType = TxType.Eip2930;
        transaction.chainId = fields[0].readUint256();
        // TODO: implement
    }

    function _decodeEip1559(
        bytes memory raw
    ) internal pure returns (Transaction memory transaction) {
        RLPReader.RLPItem[] memory fields = raw.toRLPItem().readList();

        transaction.txType = TxType.Eip1559;
        transaction.chainId = fields[0].readUint256();
        // TODO: implement
    }

    function _decodeEip4844(
        bytes memory raw
    ) internal pure returns (Transaction memory transaction) {
        RLPReader.RLPItem[] memory fields = raw.toRLPItem().readList();

        transaction.txType = TxType.Eip4844;
        transaction.chainId = fields[0].readUint256();
        // TODO: implement
    }
}
