// SPDX-Licnese-Identifier: MIT
pragma solidity ^0.8.13;

import {BLS12381} from "../lib/bls/BLS12381.sol";
import {BLSSignatureVerifier} from "../lib/bls/BLSSignatureVerifier.sol";
import {ValidatorProver} from "../lib/ssz/ValidatorProver.sol";
import {BeaconChainUtils} from "../lib/BeaconChainUtils.sol";
import {IBoltValidators} from "../interfaces/IBoltValidators.sol";

/// @title Bolt Validators
/// @notice This contract is responsible for registering validators and managing their configuration
contract BoltValidators is IBoltValidators, BLSSignatureVerifier {
    using BLS12381 for BLS12381.G1Point;

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

    /// @notice Emitted when a validator is registered
    /// @param pubkeyHash BLS public key hash of the validator
    /// @param validator Validator struct
    event ValidatorRegistered(bytes32 indexed pubkeyHash, Validator validator);

    /// @notice Constructor
    constructor() {}

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
    function getValidatorByPubkey(BLS12381.G1Point calldata pubkey) public view returns (Validator memory) {
        return getValidatorByPubkeyHash(_pubkeyHash(pubkey));
    }

    /// @notice Get a validator by its BLS public key hash
    /// @param pubkeyHash BLS public key hash of the validator
    /// @return Validator memory Validator struct
    function getValidatorByPubkeyHash(bytes32 pubkeyHash) public view returns (Validator memory) {
        return VALIDATORS[pubkeyHash];
    }

    /// @notice Get a validator by its sequence number
    /// @param sequenceNumber Sequence number of the validator
    /// @return Validator memory Validator struct
    function getValidatorBySequenceNumber(uint64 sequenceNumber) public view returns (Validator memory) {
        bytes32 pubkeyHash = sequenceNumberToPubkeyHash[sequenceNumber];
        return VALIDATORS[pubkeyHash];
    }

    /// @notice Register a single Validator and authorize a Collateral Provider and Operator for it
    /// @dev This function allows anyone to register a single Validator. We do not perform any checks.
    function registerValidatorUnsafe(
        BLS12381.G1Point calldata pubkey,
        address authorizedCollateralProvider,
        address authorizedOperator
    ) public {
        if (authorizedCollateralProvider == address(0)) {
            revert InvalidAuthorizedCollateralProvider();
        }
        if (authorizedOperator == address(0)) {
            revert InvalidAuthorizedOperator();
        }

        bytes32 pubKeyHash = _pubkeyHash(pubkey);

        VALIDATORS[pubKeyHash] = Validator({
            sequenceNumber: nextValidatorSequenceNumber,
            authorizedCollateralProvider: authorizedCollateralProvider,
            authorizedOperator: authorizedOperator,
            controller: msg.sender,
            exists: true
        });

        sequenceNumberToPubkeyHash[nextValidatorSequenceNumber] = pubKeyHash;
        nextValidatorSequenceNumber += 1;
    }

    /// @notice Register a single Validator and authorize a Collateral Provider and Operator for it
    /// @dev This function allows anyone to register a single Validator. We perform two important checks:
    /// 1. The owner of the Validator (controller) must have signed the message with its BLS private key
    /// 2. The Validator must exist on the beacon chain, which we prove with an SSZ proof.
    /// @param pubkey BLS public key for the Validator to be registered
    /// @param signature BLS signature of the registration message for the Validator
    /// @param authorizedCollateralProvider The address of the authorized collateral provider
    /// @param authorizedOperator The address of the authorized operator
    /// @param validatorProof Proof of inclusion for the Validator
    /// @param proofTimestamp The timestamp at which the proof is valid
    function registerValidator(
        BLS12381.G1Point calldata pubkey,
        BLS12381.G2Point calldata signature,
        address authorizedCollateralProvider,
        address authorizedOperator,
        ValidatorProver.ValidatorProof calldata validatorProof,
        uint64 proofTimestamp
    ) public {
        if (authorizedCollateralProvider == address(0)) {
            revert InvalidAuthorizedCollateralProvider();
        }
        if (authorizedOperator == address(0)) {
            revert InvalidAuthorizedOperator();
        }

        bytes memory message = abi.encodePacked(block.chainid, msg.sender, nextValidatorSequenceNumber);
        if (!_verifySignature(message, signature, pubkey)) {
            revert InvalidBLSSignature();
        }

        // prove the existence of the validator on the beacon chain
        ValidatorProver._proveValidator(validatorProof, proofTimestamp);

        // check if the validator already exists
        bytes32 pubKeyHash = _pubkeyHash(pubkey);
        if (VALIDATORS[pubKeyHash].exists) {
            revert ValidatorAlreadyExists();
        }

        // register the validator
        VALIDATORS[pubKeyHash] = Validator({
            sequenceNumber: nextValidatorSequenceNumber,
            authorizedCollateralProvider: authorizedCollateralProvider,
            authorizedOperator: authorizedOperator,
            controller: msg.sender,
            exists: true
        });

        sequenceNumberToPubkeyHash[nextValidatorSequenceNumber] = pubKeyHash;
        nextValidatorSequenceNumber += 1;
    }

    /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
    /// @dev This function allows anyone to register a list of Validators.
    /// @param pubkeys List of BLS public keys for the Validators to be registered
    /// @param signature BLS aggregated signature of the registration message for this batch of Validators
    /// @param authorizedCollateralProvider The address of the authorized collateral provider
    /// @param authorizedOperator The address of the authorized operator
    /// @param validatorProofs List of proofs of inclusion for the Validators
    /// @param proofTimestamp The timestamp at which all the proofs are valid
    function batchRegisterValidators(
        BLS12381.G1Point[] calldata pubkeys,
        BLS12381.G2Point calldata signature,
        address authorizedCollateralProvider,
        address authorizedOperator,
        ValidatorProver.ValidatorProof[] calldata validatorProofs,
        uint64 proofTimestamp
    ) public {
        if (authorizedCollateralProvider == address(0)) {
            revert InvalidAuthorizedCollateralProvider();
        }
        if (authorizedOperator == address(0)) {
            revert InvalidAuthorizedOperator();
        }

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

        // make sure that the timestamp is inside the EIP-4788 time window of 8191 slots
        if (!BeaconChainUtils._isWithinEIP4788Window(proofTimestamp)) {
            revert InvalidProofTimestamp();
        }

        // Register the validators and authorize the Collateral Provider and Operator for them
        for (uint256 i = 0; i < validatorsCount; i++) {
            // prove the existence of each validator on the beacon chain
            ValidatorProver._proveValidator(validatorProofs[i], proofTimestamp);

            // check if the validator already exists

            bytes32 pubKeyHash = _pubkeyHash(pubkeys[i]);
            if (VALIDATORS[pubKeyHash].exists) {
                revert ValidatorAlreadyExists();
            }

            // register the validator
            VALIDATORS[pubKeyHash] = Validator({
                sequenceNumber: expectedValidatorSequenceNumbers[i],
                authorizedCollateralProvider: authorizedCollateralProvider,
                authorizedOperator: authorizedOperator,
                controller: msg.sender,
                exists: true
            });

            sequenceNumberToPubkeyHash[expectedValidatorSequenceNumbers[i]] = pubKeyHash;
        }

        nextValidatorSequenceNumber += uint64(validatorsCount);
    }

    /// @notice Compute the hash of a BLS public key
    /// @param pubkey BLS public key
    /// @return Hash of the public key in compressed form
    function _pubkeyHash(BLS12381.G1Point memory pubkey) internal pure returns (bytes32) {
        uint256[2] memory compressedPubKey = pubkey.compress();
        return keccak256(abi.encodePacked(compressedPubKey));
    }
}
