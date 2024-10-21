// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {BLS12381} from "../lib/bls/BLS12381.sol";
import {BLSSignatureVerifier} from "../lib/bls/BLSSignatureVerifier.sol";
import {IBoltValidatorsV1} from "../interfaces/IBoltValidatorsV1.sol";
import {IBoltParametersV1} from "../interfaces/IBoltParametersV1.sol";

/// @title Bolt Validators
/// @notice This contract is responsible for registering validators and managing their configuration
/// @dev This contract is upgradeable using the UUPSProxy pattern. Storage layout remains fixed across upgrades
/// with the use of storage gaps.
/// See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
/// To validate the storage layout, use the Openzeppelin Foundry Upgrades toolkit.
/// You can also validate manually with forge: forge inspect <contract> storage-layout --pretty
contract BoltValidatorsV1 is IBoltValidatorsV1, BLSSignatureVerifier, OwnableUpgradeable, UUPSUpgradeable {
    using BLS12381 for BLS12381.G1Point;

    // ========= STORAGE =========

    /// @notice Bolt Parameters contract.
    IBoltParametersV1 public parameters;

    /// @notice Validators (aka Blockspace providers)
    /// @dev For our purpose, validators are blockspace providers for commitments.
    /// They are identified by their BLS pubkey hash.
    ///
    /// Validators can be separate from their Collateral Provider, such as in the
    /// case of non-custodial staking pools. Validators can also delegate commitment
    /// power to an Operator to make commitments on their behalf.
    mapping(bytes32 => Validator) public VALIDATORS;

    /// @notice Mapping from validator sequence number to validator pubkey hash
    /// @dev This is used internally to easily query the pubkey hash of a validator.
    mapping(uint64 => bytes32) private sequenceNumberToPubkeyHash;

    /// @notice counter of the next index to be assigned to a validator.
    /// @dev This incremental index is only used to identify validators in the registry.
    /// It is not related to the `validatorIndex` assigned by the Beacon Chain.
    uint64 internal nextValidatorSequenceNumber;

    // --> Storage layout marker: 4 slots

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     * This can be validated with the Openzeppelin Foundry Upgrades toolkit.
     *
     * Total storage slots: 50
     */
    uint256[46] private __gap;

    // ========= EVENTS =========

    /// @notice Emitted when a validator is registered
    /// @param pubkeyHash BLS public key hash of the validator
    /// @param validator Validator struct
    event ValidatorRegistered(bytes32 indexed pubkeyHash, Validator validator);

    // ========= INITIALIZER =========

    /// @notice Initializer
    /// @param _owner Address of the owner of the contract
    /// @param _parameters Address of the Bolt Parameters contract
    function initialize(address _owner, address _parameters) public initializer {
        __Ownable_init(_owner);

        parameters = IBoltParametersV1(_parameters);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

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
    /// @param pubkey BLS public key of the validator
    /// @return Validator memory Validator struct
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
    /// @param pubkey BLS public key for the Validator to be registered
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function registerValidatorUnsafe(
        BLS12381.G1Point calldata pubkey,
        uint128 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        if (!parameters.ALLOW_UNSAFE_REGISTRATION()) {
            revert UnsafeRegistrationNotAllowed();
        }

        _registerValidator(pubkey, nextValidatorSequenceNumber, maxCommittedGasLimit, authorizedOperator);
    }

    /// @notice Register a single Validator and authorize a Collateral Provider and Operator for it
    /// @dev This function allows anyone to register a single Validator. We perform an important check:
    /// The owner of the Validator (controller) must have signed the message with its BLS private key.
    ///
    /// Message format: `chainId || controller || sequenceNumber`
    /// @param pubkey BLS public key for the Validator to be registered
    /// @param signature BLS signature of the registration message for the Validator
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function registerValidator(
        BLS12381.G1Point calldata pubkey,
        BLS12381.G2Point calldata signature,
        uint128 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        bytes memory message = abi.encodePacked(block.chainid, msg.sender, nextValidatorSequenceNumber);
        if (!_verifySignature(message, signature, pubkey)) {
            revert InvalidBLSSignature();
        }

        _registerValidator(pubkey, nextValidatorSequenceNumber, maxCommittedGasLimit, authorizedOperator);
    }

    /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
    /// @dev This function allows anyone to register a list of Validators.
    /// @param pubkeys List of BLS public keys for the Validators to be registered
    /// @param signature BLS aggregated signature of the registration message for this batch of Validators
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function batchRegisterValidators(
        BLS12381.G1Point[] calldata pubkeys,
        BLS12381.G2Point calldata signature,
        uint128 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        uint256 validatorsCount = pubkeys.length;
        uint64[] memory expectedValidatorSequenceNumbers = new uint64[](validatorsCount);
        for (uint256 i = 0; i < validatorsCount; i++) {
            expectedValidatorSequenceNumbers[i] = nextValidatorSequenceNumber + uint64(i);
        }

        // Reconstruct the unique message for which we expect an aggregated signature.
        // We need the msg.sender to prevent a front-running attack by an EOA that may
        // try to register the same validators
        bytes memory message = abi.encodePacked(block.chainid, msg.sender, expectedValidatorSequenceNumbers);

        // Aggregate the pubkeys into a single pubkey to verify the aggregated signature once
        BLS12381.G1Point memory aggPubkey = _aggregatePubkeys(pubkeys);

        if (!_verifySignature(message, signature, aggPubkey)) {
            revert InvalidBLSSignature();
        }

        // Register the validators and authorize the Collateral Provider and Operator for them
        for (uint256 i = 0; i < validatorsCount; i++) {
            _registerValidator(
                pubkeys[i], expectedValidatorSequenceNumbers[i], maxCommittedGasLimit, authorizedOperator
            );
        }
    }

    /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
    /// @dev This function allows anyone to register a list of Validators.
    /// @param pubkeys List of BLS public keys for the Validators to be registered
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function batchRegisterValidatorsUnsafe(
        BLS12381.G1Point[] calldata pubkeys,
        uint128 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        if (!parameters.ALLOW_UNSAFE_REGISTRATION()) {
            revert UnsafeRegistrationNotAllowed();
        }

        uint256 validatorsCount = pubkeys.length;
        uint64[] memory expectedValidatorSequenceNumbers = new uint64[](validatorsCount);
        for (uint256 i = 0; i < validatorsCount; i++) {
            expectedValidatorSequenceNumbers[i] = nextValidatorSequenceNumber + uint64(i);
        }

        // Register the validators and authorize the Collateral Provider and Operator for them
        for (uint256 i = 0; i < validatorsCount; i++) {
            _registerValidator(
                pubkeys[i], expectedValidatorSequenceNumbers[i], maxCommittedGasLimit, authorizedOperator
            );
        }
    }

    // ========= UPDATE FUNCTIONS =========

    /// @notice Update the maximum gas limit that a validator can commit for preconfirmations
    /// @dev Only the `controller` of the validator can update this value.
    /// @param pubkeyHash The hash of the BLS public key of the validator
    /// @param maxCommittedGasLimit The new maximum gas limit
    function updateMaxCommittedGasLimit(bytes32 pubkeyHash, uint128 maxCommittedGasLimit) public {
        Validator storage validator = VALIDATORS[pubkeyHash];

        if (!validator.exists) {
            revert ValidatorDoesNotExist();
        }

        if (msg.sender != validator.controller) {
            revert UnauthorizedCaller();
        }

        validator.maxCommittedGasLimit = maxCommittedGasLimit;
    }

    // ========= HELPERS =========

    /// @notice Internal helper to add a validator to the registry
    /// @param pubkey BLS public key of the validator
    /// @param sequenceNumber Sequence number of the validator
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator Address of the authorized operator
    function _registerValidator(
        BLS12381.G1Point calldata pubkey,
        uint64 sequenceNumber,
        uint128 maxCommittedGasLimit,
        address authorizedOperator
    ) internal {
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
            maxCommittedGasLimit: maxCommittedGasLimit,
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
