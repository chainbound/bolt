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

    /// @dev Only works with block headers that are less than 256 blocks old.
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
        // RLP decode the header
        // https://github.com/ethereum/go-ethereum/blob/master/core/types/block.go
        RLPReader.RLPItem[] memory headerFields = header.toRLPItem().readList();
        transactionsRoot = headerFields[4].readBytes32();
        blockNumber = headerFields[8].readUint256();
        gasLimit = headerFields[9].readUint256();
        gasUsed = headerFields[10].readUint256();
        timestamp = headerFields[11].readUint256();
        baseFee = headerFields[15].readUint256();

        if (blockhash(blockNumber) == bytes32(0) || blockNumber < block.number - 256) {
            revert BlockIsTooOld();
        }

        // verify that the block hash matches the one in the EVM
        if (keccak256(header) != blockhash(blockNumber)) {
            revert InvalidBlockHash();
        }
    }

    /// @notice Prove the account data of an account at a given state root.
    /// @dev This function assumes that the provided state root and account proof match.
    /// @param account The account address to prove.
    /// @param stateRoot The TRUSTED state root to prove against. Checking how the state root is obtained
    /// is the responsibility of the caller.
    /// @param accountProof The MPT account proof to prove the account data.
    /// @return nonce The nonce of the account at the given state root height.
    /// @return balance The balance of the account at the given state root height.
    function proveAccountData(
        address account,
        bytes32 stateRoot,
        bytes calldata accountProof
    ) public returns (uint256 nonce, uint256 balance) {
        (bool exists, bytes memory accountRLP) =
            SecureMerkleTrie.get(abi.encodePacked(account), accountProof, stateRoot);

        if (!exists) {
            revert AccountDoesNotExist();
        }

        // decode the account RLP into nonce and balance
        RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();
        nonce = accountFields[0].readUint256();
        balance = accountFields[1].readUint256();
    }
}
