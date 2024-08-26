// SPDX-Licnese-Identifier: MIT
pragma solidity ^0.8.13;

import {BLS12381} from "../lib/BLS12381.sol";
import {BeaconChainUtils} from "../lib/BeaconChainUtils.sol";
import {ValidatorProver} from "../lib/ValidatorProver.sol";
import {IBoltValidators} from "../interfaces/IBoltValidators.sol";

/// @title Bolt Validators
/// @notice This contract is responsible for registering validators and managing their configuration
contract BoltValidators is IBoltValidators {
    using BLS12381 for BLS12381.G1Point;

    /// @notice Validators (aka Blockspace providers)
    /// @dev For our purpose, validators are blockspace providers for commitments.
    /// They are identified by their BLS pubkey hash.
    ///
    /// Validators can be separate from their Collateral Provider, such as in the
    /// case of non-custodial staking pools. Validators can also delegate commitment
    /// power to an Operator to make commitments on their behalf.
    mapping(bytes32 => Validator) public VALIDATORS;

    /// @notice counter of the next index to be assigned to a validator.
    /// @dev This incremental index is only used to identify validators in the registry.
    /// It is not related to the `validatorIndex` assigned by the Beacon Chain.
    uint64 internal nextValidatorSequenceNumber;

    constructor() {}

    function getValidator(BLS12381.G1Point calldata pubkey) public view returns (Validator memory) {
        return VALIDATORS[_pubkeyHash(pubkey)];
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

        // Verify the aggregated signature once for all pubkeys
        if (!_verifyAggregatedBLSSignature(pubkeys, signature, message)) {
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
                sequenceNumber: nextValidatorSequenceNumber,
                authorizedCollateralProvider: authorizedCollateralProvider,
                authorizedOperator: authorizedOperator,
                controller: msg.sender,
                exists: true
            });
        }

        nextValidatorSequenceNumber += uint64(validatorsCount);
    }

    function _batchProveValidators(
        BLS12381.G1Point[] calldata pubkeys,
        uint64[] calldata validatorIndexes,
        uint64 blockNumber
    ) internal {}

    /// @notice Verify a BLS aggregated signature
    /// @param pubkeys List of BLS public keys that were used to create the aggregated signature
    /// @param signature Aggregated BLS signature
    /// @param message Message that was signed
    /// @return True if the signature is valid, false otherwise
    function _verifyAggregatedBLSSignature(
        BLS12381.G1Point[] calldata pubkeys,
        BLS12381.G2Point calldata signature,
        bytes memory message
    ) internal pure returns (bool) {
        // TODO: verify the aggregated signature using the precompile lib
        // This can be tested only after Pectra, for now just return true

        // silence warnings
        pubkeys;
        signature;
        message;

        return true;
    }

    /// @notice Compute the hash of a BLS public key
    /// @param pubkey BLS public key
    /// @return Hash of the public key in compressed form
    function _pubkeyHash(BLS12381.G1Point memory pubkey) internal pure returns (bytes32) {
        uint256[2] memory compressedPubKey = pubkey.compress();
        return keccak256(abi.encodePacked(compressedPubKey));
    }
}
