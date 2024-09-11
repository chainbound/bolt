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

    /// @notice Prove the block header data of a recent block.
    /// @dev Only works with block headers that are less than 256 blocks old.
    /// @param header The RLP-encoded block header to prove.
    function proveRecentBlockHeaderData(
        bytes calldata header
    )
        public
        view
        returns (
            bytes32 transactionsRoot,
            uint256 blockNumber,
            uint256 gasLimit,
            uint256 gasUsed,
            uint256 timestamp,
            uint256 baseFee
        )
    {
        // RLP decode the block header and extract the necessary fields
        // ref: https://github.com/ethereum/go-ethereum/blob/master/core/types/block.go
        RLPReader.RLPItem[] memory headerFields = header.toRLPItem().readList();
        transactionsRoot = headerFields[4].readBytes32();
        blockNumber = headerFields[8].readUint256();
        gasLimit = headerFields[9].readUint256();
        gasUsed = headerFields[10].readUint256();
        timestamp = headerFields[11].readUint256();
        baseFee = headerFields[15].readUint256();

        bytes32 trustedBlockHash = blockhash(blockNumber);
        if (trustedBlockHash == bytes32(0) || blockNumber < block.number - 256) {
            revert BlockIsTooOld();
        }

        if (keccak256(header) != trustedBlockHash) {
            revert InvalidBlockHash();
        }
    }

    /// @notice Prove the account data of an account at a given state root.
    /// @dev This function assumes that the provided state root and account proof match.
    /// @param account The account address to prove.
    /// @param trustedStateRoot The state root to prove against.
    /// @param accountProof The MPT account proof to prove the account data.
    /// @return nonce The nonce of the account at the given state root height.
    /// @return balance The balance of the account at the given state root height.
    function proveAccountData(
        address account,
        bytes32 trustedStateRoot,
        bytes calldata accountProof
    ) public pure returns (uint256 nonce, uint256 balance) {
        (bool exists, bytes memory accountRLP) =
            SecureMerkleTrie.get(abi.encodePacked(account), accountProof, trustedStateRoot);

        if (!exists) {
            revert AccountDoesNotExist();
        }

        // RLP decode the account and extract the nonce and balance
        RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();
        nonce = accountFields[0].readUint256();
        balance = accountFields[1].readUint256();
    }
}
