// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {BLS12381} from "../lib/bls/BLS12381.sol";
import {ValidatorProver} from "../lib/ssz/ValidatorProver.sol";

interface IBoltValidators {
    /// @notice Validator
    struct Validator {
        // the incremental sequence number assigned to the validator
        uint64 sequenceNumber;
        // the entity authorized to deposit collateral for the validator
        // to add credibility to its commitments
        address authorizedCollateralProvider;
        // the entity authorized to make commitments on behalf of the validator
        address authorizedOperator;
        // the EOA that registered the validator and can update its configuration
        address controller;
        // whether the validator exists in the registry
        bool exists;
    }

    error InvalidBLSSignature();
    error InvalidAuthorizedCollateralProvider();
    error InvalidAuthorizedOperator();
    error ValidatorAlreadyExists();
    error ValidatorDoesNotExist();
    error UnsafeRegistrationNotAllowed();

    function getAllValidators() external view returns (Validator[] memory);

    function getValidatorByPubkey(BLS12381.G1Point calldata pubkey) external view returns (Validator memory);

    function getValidatorByPubkeyHash(bytes32 pubkeyHash) external view returns (Validator memory);

    function getValidatorBySequenceNumber(uint64 sequenceNumber) external view returns (Validator memory);

    function registerValidatorUnsafe(
        BLS12381.G1Point calldata pubkey,
        address authorizedCollateralProvider,
        address authorizedOperator
    ) external;

    function registerValidator(
        BLS12381.G1Point calldata pubkey,
        BLS12381.G2Point calldata signature,
        address authorizedCollateralProvider,
        address authorizedOperator
    ) external;

    function batchRegisterValidators(
        BLS12381.G1Point[] calldata pubkeys,
        BLS12381.G2Point calldata signature,
        address authorizedCollateralProvider,
        address authorizedOperator
    ) external;
}
