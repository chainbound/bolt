// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {SSZ} from "./SSZ.sol";
import {SSZContainers} from "./SSZContainers.sol";
import {BeaconChainUtils} from "./BeaconChainUtils.sol";

/// @title ValidatorProver
/// @notice Proves a validator's inclusion in the Beacon Chain.
library ValidatorProver {
    uint64 constant VALIDATOR_REGISTRY_LIMIT = 2 ** 40;

    /// @dev Generalized index of the first validator struct root in the registry.
    uint256 constant DENEB_VALIDATOR_GENERALIZED_INDEX_OFFSET = 798_245_441_765_376;

    error RootNotFound();
    error IndexOutOfRange();
    error InvalidProof();

    struct ValidatorProof {
        bytes32[] validatorProof;
        SSZContainers.Validator validator;
        uint64 validatorIndex;
    }

    /// @notice Prove a validator's inclusion in a beacon chain.
    /// @param proof The proof of inclusion for the validator
    /// @param ts The timestamp at which the proof is valid
    function _proveValidator(ValidatorProof calldata proof, uint64 ts) public view {
        if (proof.validatorIndex >= VALIDATOR_REGISTRY_LIMIT) {
            revert IndexOutOfRange();
        }

        uint256 generalizedIndex = DENEB_VALIDATOR_GENERALIZED_INDEX_OFFSET + proof.validatorIndex;
        bytes32 validatorRoot = SSZContainers._validatorHashTreeRoot(proof.validator);
        bytes32 blockRoot = BeaconChainUtils._getBeaconBlockRootAtTimestamp(ts);

        if (!SSZ._verifyProof(proof.validatorProof, blockRoot, validatorRoot, generalizedIndex)) {
            revert InvalidProof();
        }
    }
}
