// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {SecureMerkleTrie} from "../lib/trie/SecureMerkleTrie.sol";
import {RLPReader} from "../lib/rlp/RLPReader.sol";

contract BoltChallenger {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    error BlockIsTooOld();
    error InvalidBlockHash();
    error AccountDoesNotExist();

    constructor() {}

    function openChallenge() public {
        // unimplemented!();
    }

    function resolveChallenge(
        uint256 challengeId
    ) public {
        // unimplemented!();
    }

    /// @notice Decode the block header fields from an RLP-encoded block header.
    /// @param headerRLP The RLP-encoded block header to decode
    function _decodeBlockHeaderRLP(
        bytes calldata headerRLP
    )
        internal
        pure
        returns (
            bytes32 transactionsRoot,
            uint256 blockNumber,
            uint256 timestamp,
            uint256 baseFee
        )
    {
        RLPReader.RLPItem[] memory headerFields = header.toRLPItem().readList();

        transactionsRoot = headerFields[4].readBytes32();
        blockNumber = headerFields[8].readUint256();
        timestamp = headerFields[11].readUint256();
        baseFee = headerFields[15].readUint256();
    }

    function _decodeAccountRLP(
        bytes calldata accountRLP
    ) internal pure returns (uint256 nonce, uint256 balance) {
        RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();

        nonce = accountFields[0].readUint256();
        balance = accountFields[1].readUint256();
    }

    function _decodeTransactionRLP(
        bytes calldata transactionRLP
    ) internal pure returns (uint256 nonce, uint256 gasPrice, uint256 gasLimit) {
        RLPReader.RLPItem[] memory transactionFields = transactionRLP.toRLPItem().readList();

        nonce = transactionFields[0].readUint256();
        gasPrice = transactionFields[1].readUint256();
        gasLimit = transactionFields[2].readUint256();
    }

    // /// @notice Prove the account data of an account at a given state root.
    // /// @dev This function assumes that the provided state root and account proof match.
    // /// @param account The account address to prove.
    // /// @param trustedStateRoot The state root to prove against.
    // /// @param accountProof The MPT account proof to prove the account data.
    // /// @return nonce The nonce of the account at the given state root height.
    // /// @return balance The balance of the account at the given state root height.
    // function proveAccountData(
    //     address account,
    //     bytes32 trustedStateRoot,
    //     bytes calldata accountProof
    // ) public pure returns (uint256 nonce, uint256 balance) {
    //     (bool exists, bytes memory accountRLP) =
    //         SecureMerkleTrie.get(abi.encodePacked(account), accountProof, trustedStateRoot);

    //     if (!exists) {
    //         revert AccountDoesNotExist();
    //     }

    //     // RLP decode the account and extract the nonce and balance
    //     RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();
    //     nonce = accountFields[0].readUint256();
    //     balance = accountFields[1].readUint256();
    // }
}
