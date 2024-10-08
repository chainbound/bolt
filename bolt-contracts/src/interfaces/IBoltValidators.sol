// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {BLS12381} from "../lib/bls/BLS12381.sol";

interface IBoltValidators {
    /// @notice Validator info
    struct Validator {
        // whether the validator exists in the registry
        bool exists;
        // the incremental sequence number assigned to the validator
        uint64 sequenceNumber;
        // the maximum amount of gas that the validator can consume with preconfirmations
        // in a single slot. Operators must respect this limit when making commitments.
        uint128 maxCommittedGasLimit;
        // the entity authorized to make commitments on behalf of the validator
        address authorizedOperator;
        // the EOA that registered the validator and can update its configuration
        address controller;
    }

    struct ProposerStatus {
        bytes32 pubkeyHash;
        bool active;
        address operator;
        string operatorRPC;
        address[] collaterals;
        uint256[] amounts;
    }

    error InvalidBLSSignature();
    error InvalidAuthorizedCollateralProvider();
    error InvalidAuthorizedOperator();
    error ValidatorAlreadyExists();
    error ValidatorDoesNotExist();
    error UnsafeRegistrationNotAllowed();
    error UnauthorizedCaller();

    function getAllValidators() external view returns (Validator[] memory);

    function getValidatorByPubkey(
        BLS12381.G1Point calldata pubkey
    ) external view returns (Validator memory);

    function getValidatorByPubkeyHash(
        bytes32 pubkeyHash
    ) external view returns (Validator memory);

    function getValidatorBySequenceNumber(
        uint64 sequenceNumber
    ) external view returns (Validator memory);

    function registerValidatorUnsafe(
        BLS12381.G1Point calldata pubkey,
        uint128 maxCommittedGasLimit,
        address authorizedOperator
    ) external;

    function registerValidator(
        BLS12381.G1Point calldata pubkey,
        BLS12381.G2Point calldata signature,
        uint128 maxCommittedGasLimit,
        address authorizedOperator
    ) external;

    function batchRegisterValidators(
        BLS12381.G1Point[] calldata pubkeys,
        BLS12381.G2Point calldata signature,
        uint128 maxCommittedGasLimit,
        address authorizedOperator
    ) external;

    function batchRegisterValidatorsUnsafe(
        BLS12381.G1Point[] calldata pubkeys,
        uint128 maxCommittedGasLimit,
        address authorizedOperator
    ) external;

    function updateMaxCommittedGasLimit(bytes32 pubkeyHash, uint128 maxCommittedGasLimit) external;
}
