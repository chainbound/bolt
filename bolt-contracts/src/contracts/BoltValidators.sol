// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {BLS12381} from "../lib/bls/BLS12381.sol";
import {BLSSignatureVerifier} from "../lib/bls/BLSSignatureVerifier.sol";
import {IBoltValidators} from "../interfaces/IBoltValidators.sol";

/// @title Bolt Validators
/// @notice This contract is responsible for registering validators and managing their configuration
contract BoltValidators is IBoltValidators, BLSSignatureVerifier, Ownable {
    using BLS12381 for BLS12381.G1Point;

    // ========= STORAGE =========

    /// @notice Validators (aka Blockspace providers)
    /// @dev For our purpose, validators are blockspace providers for commitments.
    /// They are identified by their BLS pubkey hash.
    ///
    /// Validators can be separate from their Collateral Provider, such as in the
    /// case of non-custodial staking pools. Validators can also delegate commitment
    /// power to an Operator to make commitments on their behalf.
    mapping(bytes32 => Validator) public VALIDATORS;

    /// @notice Whether to allow unsafe registration of validators
    /// @dev Until the BLS12_381 precompile is live, we need to allow unsafe registration
    /// which means we don't check the BLS signature of the validator pubkey.
    bool public ALLOW_UNSAFE_REGISTRATION = true;

    /// @notice Mapping from validator sequence number to validator pubkey hash
    /// @dev This is used internally to easily query the pubkey hash of a validator.
    mapping(uint64 => bytes32) private sequenceNumberToPubkeyHash;

    /// @notice counter of the next index to be assigned to a validator.
    /// @dev This incremental index is only used to identify validators in the registry.
    /// It is not related to the `validatorIndex` assigned by the Beacon Chain.
    uint64 internal nextValidatorSequenceNumber;

    // ========= EVENTS =========

    /// @notice Emitted when a validator is registered
    /// @param pubkeyHash BLS public key hash of the validator
    /// @param validator Validator struct
    event ValidatorRegistered(bytes32 indexed pubkeyHash, Validator validator);

    // ========= CONSTRUCTOR =========

    /// @notice Constructor
    /// @param _owner Address of the owner of the contract
    constructor(address _owner) Ownable(_owner) {}

    // ========= ADMIN FUNCTIONS =========

    /// @notice Enable or disable the use of the BLS precompile
    /// @param allowUnsafeRegistration Whether to allow unsafe registration of validators
    function setAllowUnsafeRegistration(
        bool allowUnsafeRegistration
    ) public onlyOwner {
        ALLOW_UNSAFE_REGISTRATION = allowUnsafeRegistration;
    }

    // ========= VIEW FUNCTIONS =========

    /// @notice Get all validators
    /// @dev This function should be used with caution as it can return a large amount of data.
    /// @return Validator[] memory Array of validator structs
    function getAllValidators() public view returns (Validator[] memory) {
        uint256 validatorCount = nextValidatorSequenceNumber;
        Validator[] memory validators = new Validator[](validatorCount);
        for (uint256 i = 0; i < validatorCount; i++) {
            bytes32 pubkeyHash = sequenceNumberToPubkeyHash[uint64(i)];
            validators[i] = VALIDATORS[pubkeyHash];
        }
        return validators;
    }

    /// @notice Get a validator by its BLS public key
    function getValidatorByPubkey(
        BLS12381.G1Point calldata pubkey
    ) public view returns (Validator memory) {
        return getValidatorByPubkeyHash(_pubkeyHash(pubkey));
    }

    /// @notice Get a validator by its BLS public key hash
    /// @param pubkeyHash BLS public key hash of the validator
    /// @return Validator memory Validator struct
    function getValidatorByPubkeyHash(
        bytes32 pubkeyHash
    ) public view returns (Validator memory) {
        Validator memory validator = VALIDATORS[pubkeyHash];
        if (!validator.exists) {
            revert ValidatorDoesNotExist();
        }
        return validator;
    }

    /// @notice Get a validator by its sequence number
    /// @param sequenceNumber Sequence number of the validator
    /// @return Validator memory Validator struct
    function getValidatorBySequenceNumber(
        uint64 sequenceNumber
    ) public view returns (Validator memory) {
        bytes32 pubkeyHash = sequenceNumberToPubkeyHash[sequenceNumber];
        return VALIDATORS[pubkeyHash];
    }

    // ========= REGISTRATION LOGIC =========

    /// @notice Register a single Validator and authorize a Collateral Provider and Operator for it
    /// @dev This function allows anyone to register a single Validator. We do not perform any checks.
    function registerValidatorUnsafe(
        BLS12381.G1Point calldata pubkey,
        address authorizedCollateralProvider,
        address authorizedOperator
    ) public {
        if (!ALLOW_UNSAFE_REGISTRATION) {
            revert UnsafeRegistrationNotAllowed();
        }

        _registerValidator(
            pubkey,
            nextValidatorSequenceNumber,
            authorizedCollateralProvider,
            authorizedOperator
        );
    }

    /// @notice Register a single Validator and authorize a Collateral Provider and Operator for it
    /// @dev This function allows anyone to register a single Validator. We perform an important check:
    /// The owner of the Validator (controller) must have signed the message with its BLS private key.
    /// @param pubkey BLS public key for the Validator to be registered
    /// @param signature BLS signature of the registration message for the Validator
    /// @param authorizedCollateralProvider The address of the authorized collateral provider
    /// @param authorizedOperator The address of the authorized operator
    function registerValidator(
        BLS12381.G1Point calldata pubkey,
        BLS12381.G2Point calldata signature,
        address authorizedCollateralProvider,
        address authorizedOperator
    ) public {
        bytes memory message = abi.encodePacked(
            block.chainid,
            msg.sender,
            nextValidatorSequenceNumber
        );
        if (!_verifySignature(message, signature, pubkey)) {
            revert InvalidAuthorizedCollateralProvider();
        }

        _registerValidator(
            pubkey,
            nextValidatorSequenceNumber,
            authorizedCollateralProvider,
            authorizedOperator
        );
    }

    /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
    /// @dev This function allows anyone to register a list of Validators.
    /// @param pubkeys List of BLS public keys for the Validators to be registered
    /// @param signature BLS aggregated signature of the registration message for this batch of Validators
    /// @param authorizedCollateralProvider The address of the authorized collateral provider
    /// @param authorizedOperator The address of the authorized operator
    function batchRegisterValidators(
        BLS12381.G1Point[] calldata pubkeys,
        BLS12381.G2Point calldata signature,
        address authorizedCollateralProvider,
        address authorizedOperator
    ) public {
        uint256 validatorsCount = pubkeys.length;
        uint64[] memory expectedValidatorSequenceNumbers = new uint64[](
            validatorsCount
        );
        for (uint256 i = 0; i < validatorsCount; i++) {
            expectedValidatorSequenceNumbers[i] =
                nextValidatorSequenceNumber +
                uint64(i);
        }

        // Reconstruct the unique message for which we expect an aggregated signature.
        // We need the msg.sender to prevent a front-running attack by an EOA that may
        // try to register the same validators
        bytes memory message = abi.encodePacked(
            block.chainid,
            msg.sender,
            expectedValidatorSequenceNumbers
        );

        // Aggregate the pubkeys into a single pubkey to verify the aggregated signature once
        BLS12381.G1Point memory aggPubkey = _aggregatePubkeys(pubkeys);

        if (!_verifySignature(message, signature, aggPubkey)) {
            revert InvalidBLSSignature();
        }

        // Register the validators and authorize the Collateral Provider and Operator for them
        for (uint256 i = 0; i < validatorsCount; i++) {
            _registerValidator(
                pubkeys[i],
                expectedValidatorSequenceNumbers[i],
                authorizedCollateralProvider,
                authorizedOperator
            );
        }
    }

    /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
    /// @dev This function allows anyone to register a list of Validators.
    /// @param pubkeys List of BLS public keys for the Validators to be registered
    /// @param authorizedCollateralProvider The address of the authorized collateral provider
    /// @param authorizedOperator The address of the authorized operator
    function batchRegisterValidatorsUnsafe(
        BLS12381.G1Point[] calldata pubkeys,
        address authorizedCollateralProvider,
        address authorizedOperator
    ) public {
        if (!ALLOW_UNSAFE_REGISTRATION) {
            revert UnsafeRegistrationNotAllowed();
        }

        uint256 validatorsCount = pubkeys.length;
        uint64[] memory expectedValidatorSequenceNumbers = new uint64[](
            validatorsCount
        );
        for (uint256 i = 0; i < validatorsCount; i++) {
            expectedValidatorSequenceNumbers[i] =
                nextValidatorSequenceNumber +
                uint64(i);
        }

        // Register the validators and authorize the Collateral Provider and Operator for them
        for (uint256 i = 0; i < validatorsCount; i++) {
            _registerValidator(
                pubkeys[i],
                expectedValidatorSequenceNumbers[i],
                authorizedCollateralProvider,
                authorizedOperator
            );
        }
    }

    // ========= HELPERS =========

    /// @notice Internal helper to add a validator to the registry
    /// @param pubkey BLS public key of the validator
    /// @param sequenceNumber Sequence number of the validator
    /// @param authorizedCollateralProvider Address of the authorized collateral provider
    /// @param authorizedOperator Address of the authorized operator
    function _registerValidator(
        BLS12381.G1Point calldata pubkey,
        uint64 sequenceNumber,
        address authorizedCollateralProvider,
        address authorizedOperator
    ) internal {
        if (authorizedCollateralProvider == address(0)) {
            revert InvalidAuthorizedCollateralProvider();
        }
        if (authorizedOperator == address(0)) {
            revert InvalidAuthorizedOperator();
        }

        bytes32 pubKeyHash = _pubkeyHash(pubkey);

        // check if the validator already exists
        if (VALIDATORS[pubKeyHash].exists) {
            revert ValidatorAlreadyExists();
        }

        Validator memory newValidator = Validator({
            sequenceNumber: sequenceNumber,
            authorizedCollateralProvider: authorizedCollateralProvider,
            authorizedOperator: authorizedOperator,
            controller: msg.sender,
            exists: true
        });

        // register the validator
        VALIDATORS[pubKeyHash] = newValidator;
        emit ValidatorRegistered(pubKeyHash, newValidator);

        sequenceNumberToPubkeyHash[sequenceNumber] = pubKeyHash;
        nextValidatorSequenceNumber += 1;
    }

    /// @notice Compute the hash of a BLS public key
    /// @param pubkey BLS public key
    /// @return Hash of the public key in compressed form
    function _pubkeyHash(
        BLS12381.G1Point memory pubkey
    ) internal pure returns (bytes32) {
        uint256[2] memory compressedPubKey = pubkey.compress();
        return keccak256(abi.encodePacked(compressedPubKey));
    }
}
