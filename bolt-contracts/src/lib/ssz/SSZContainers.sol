// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {SSZ} from "./SSZ.sol";

library SSZContainers {
    /// @notice a Validator SSZ container
    /// @dev As defined in https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
    struct Validator {
        bytes pubkey;
        bytes32 withdrawalCredentials;
        uint64 effectiveBalance;
        bool slashed;
        uint64 activationEligibilityEpoch;
        uint64 activationEpoch;
        uint64 exitEpoch;
        uint64 withdrawableEpoch;
    }

    /// @notice a Beacon block header SSZ container
    /// @dev As defined in https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblockheader
    struct BeaconBlockHeader {
        uint64 slot;
        uint64 proposerIndex;
        bytes32 parentRoot;
        bytes32 stateRoot;
        bytes32 bodyRoot;
    }

    /// @notice Computes the hash tree root of a validator SSZ container
    function _validatorHashTreeRoot(Validator memory validator) internal view returns (bytes32) {
        bytes32 pubkeyRoot;
        uint256 _sha256 = SSZ.SHA256_PRECOMPILE;

        assembly {
            // Dynamic data types such as bytes are stored at the specified offset.
            let offset := mload(validator)
            // Call sha256 precompile with the pubkey pointer
            let result := staticcall(gas(), _sha256, add(offset, 32), 0x40, 0x00, 0x20)
            // Precompile returns no data on OutOfGas error.
            if eq(result, 0) { revert(0, 0) }

            pubkeyRoot := mload(0x00)
        }

        bytes32[] memory nodes = new bytes32[](8);
        nodes[0] = pubkeyRoot;
        nodes[1] = validator.withdrawalCredentials;
        nodes[2] = SSZ._toLittleEndian(validator.effectiveBalance);
        nodes[3] = SSZ._toLittleEndian(validator.slashed);
        nodes[4] = SSZ._toLittleEndian(validator.activationEligibilityEpoch);
        nodes[5] = SSZ._toLittleEndian(validator.activationEpoch);
        nodes[6] = SSZ._toLittleEndian(validator.exitEpoch);
        nodes[7] = SSZ._toLittleEndian(validator.withdrawableEpoch);

        return SSZ._hashTreeRoot(nodes, 8);
    }

    /// @notice Computes the hash tree root of a beacon block header SSZ container
    function _beaconHeaderHashTreeRoot(BeaconBlockHeader memory header) internal view returns (bytes32) {
        bytes32[] memory nodes = new bytes32[](8);
        nodes[0] = SSZ._toLittleEndian(header.slot);
        nodes[1] = SSZ._toLittleEndian(header.proposerIndex);
        nodes[2] = header.parentRoot;
        nodes[3] = header.stateRoot;
        nodes[4] = header.bodyRoot;
        nodes[5] = bytes32(0);
        nodes[6] = bytes32(0);
        nodes[7] = bytes32(0);

        return SSZ._hashTreeRoot(nodes, 8);
    }

    /// @notice Computes the hash tree root of an RLP-encoded signed transaction (raw bytes)
    function _transactionHashTreeRoot(bytes memory transaction) internal view returns (bytes32) {
        uint256 chunkCount = (transaction.length + 31) / 32;
        bytes32[] memory nodes = new bytes32[](chunkCount);

        // TODO: this is most likely wrong, needs fix according to ssz specs
        for (uint256 i = 0; i < chunkCount; i++) {
            uint256 start = i * 32;
            uint256 end = start + 32;
            if (end > transaction.length) {
                end = transaction.length;
            }
            bytes memory chunk = new bytes(32);
            for (uint256 j = start; j < end; j++) {
                chunk[j - start] = transaction[j];
            }
            nodes[i] = keccak256(chunk);
        }

        return SSZ._hashTreeRoot(nodes, uint8(chunkCount));
    }
}
