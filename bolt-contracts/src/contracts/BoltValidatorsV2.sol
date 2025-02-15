// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {BLS12381} from "../lib/bls/BLS12381.sol";
import {BLSSignatureVerifier} from "../lib/bls/BLSSignatureVerifier.sol";
import {ValidatorsLib} from "../lib/ValidatorsLib.sol";
import {URCMerkleTree} from "../lib/URCMerkleTree.sol";
import {IBoltValidatorsV2} from "../interfaces/IBoltValidatorsV2.sol";
import {IBoltParametersV1} from "../interfaces/IBoltParametersV1.sol";
import {IBoltManagerV2} from "../interfaces/IBoltManagerV2.sol";
import {ICredibleCommitmentCurationProvider} from "../interfaces/ICredibleCommitmentCurationProvider.sol";

/// @title Bolt Validators
/// @notice This contract is responsible for registering validators and managing their configuration
/// @dev This contract is upgradeable using the UUPSProxy pattern. Storage layout remains fixed across upgrades
/// with the use of storage gaps.
/// See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
/// To validate the storage layout, use the Openzeppelin Foundry Upgrades toolkit.
/// You can also validate manually with forge: forge inspect <contract> storage-layout --pretty
contract BoltValidatorsV2 is IBoltValidatorsV2, BLSSignatureVerifier, OwnableUpgradeable, UUPSUpgradeable {
    using BLS12381 for BLS12381.G1Point;
    using ValidatorsLib for ValidatorsLib.ValidatorSet;

    // ========= STORAGE =========

    /// @notice Bolt Parameters contract.
    IBoltParametersV1 public parameters;

    IBoltManagerV2 public manager;

    /// @notice Validators (aka Blockspace providers)
    /// @dev This struct occupies 6 storage slots.
    ValidatorsLib.ValidatorSet internal VALIDATORS;

    // --> Storage layout marker: 7 slots

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     * This can be validated with the Openzeppelin Foundry Upgrades toolkit.
     *
     * Total storage slots: 50
     */
    uint256[43] private __gap;

    // ========= EVENTS =========

    /// @notice Emitted when a validator is registered
    /// @param pubkeyHash BLS public key hash of the validator
    event ValidatorRegistered(bytes32 indexed pubkeyHash);

    // ========= INITIALIZER =========

    /// @notice Initializer
    /// @param _owner Address of the owner of the contract
    /// @param _parameters Address of the Bolt Parameters contract
    function initialize(address _owner, address _parameters) public initializer {
        __Ownable_init(_owner);

        parameters = IBoltParametersV1(_parameters);
    }

    function initializeV2(address _owner, address _parameters) public reinitializer(2) {
        __Ownable_init(_owner);

        parameters = IBoltParametersV1(_parameters);
    }

    function setManager(address _manager) external onlyOwner {
        if (IBoltManagerV2(_manager).validators() != address(this)) {
            revert InvalidManager();
        }

        manager = IBoltManagerV2(_manager);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // ========= VIEW FUNCTIONS =========

    /// @notice Get all validators in the system
    /// @dev This function should be used with caution as it can return a large amount of data.
    /// @return ValidatorInfo[] Array of validator info structs
    function getAllValidators() public view returns (ValidatorInfo[] memory) {
        ValidatorsLib._Validator[] memory _vals = VALIDATORS.getAll();
        ValidatorInfo[] memory vals = new ValidatorInfo[](_vals.length);
        for (uint256 i = 0; i < _vals.length; i++) {
            vals[i] = _getValidatorInfo(_vals[i]);
        }
        return vals;
    }

    /// @notice Get a validator by its BLS public key
    /// @param pubkey BLS public key of the validator
    /// @return ValidatorInfo struct
    function getValidatorByPubkey(
        BLS12381.G1Point calldata pubkey
    ) public view returns (ValidatorInfo memory) {
        return getValidatorByPubkeyHash(hashPubkey(pubkey));
    }

    /// @notice Get a validator by its BLS public key hash
    /// @param pubkeyHash BLS public key hash of the validator
    /// @return ValidatorInfo struct
    function getValidatorByPubkeyHash(
        bytes20 pubkeyHash
    ) public view returns (ValidatorInfo memory) {
        ValidatorsLib._Validator memory _val = VALIDATORS.get(pubkeyHash);
        return _getValidatorInfo(_val);
    }

    // ========= REGISTRATION LOGIC =========

    /// @notice Register a single Validator and authorize a Collateral Provider and Operator for it
    /// @dev This function allows anyone to register a single Validator. We do not perform any checks.
    /// @param pubkeyHash BLS public key hash for the Validator to be registered
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function registerValidatorUnsafe(
        bytes20 pubkeyHash,
        uint32 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        if (!parameters.ALLOW_UNSAFE_REGISTRATION()) {
            revert UnsafeRegistrationNotAllowed();
        }

        _registerValidator(pubkeyHash, authorizedOperator, maxCommittedGasLimit);
    }

    /// @notice Register a single Validator and authorize an Operator for it.
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
        uint32 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        uint32 sequenceNumber = uint32(VALIDATORS.length() + 1);
        bytes memory message = abi.encodePacked(block.chainid, msg.sender, sequenceNumber);
        if (!_verifySignature(message, signature, pubkey)) {
            revert InvalidBLSSignature();
        }

        ICredibleCommitmentCurationProvider curator = ICredibleCommitmentCurationProvider(manager.getOperatorCurator(authorizedOperator));
        if (address(curator) != address(0)) {
            curator.hookOnlyApprovedRegistrationRoot(regRoot);
        }

        _registerValidator(hashPubkey(pubkey), authorizedOperator, maxCommittedGasLimit);
    }

    /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
    /// @dev This function allows anyone to register a list of Validators.
    /// @param pubkeys List of BLS public keys for the Validators to be registered
    /// @param signature BLS aggregated signature of the registration message for this batch of Validators
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function batchRegisterValidators(
        BLS12381.G1Point[] calldata pubkeys,
        BLS12381.G2Point[] calldata signatures,
        uint32 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        uint32[] memory expectedValidatorSequenceNumbers = new uint32[](pubkeys.length);
        uint32 nextValidatorSequenceNumber = uint32(VALIDATORS.length() + 1);
        for (uint32 i = 0; i < pubkeys.length; i++) {
            expectedValidatorSequenceNumbers[i] = nextValidatorSequenceNumber + i;
        }

        // Reconstruct the unique message for which we expect an aggregated signature.
        // We need the msg.sender to prevent a front-running attack by an EOA that may
        // try to register the same validators
        bytes memory message = abi.encodePacked(block.chainid, msg.sender, expectedValidatorSequenceNumbers);

        bytes32 registrationRoot = _merkleizeRegistrations(pubkeys, signatures);


        // // Aggregate the pubkeys into a single pubkey to verify the aggregated signature once
        // BLS12381.G1Point memory aggPubkey = _aggregatePubkeys(pubkeys);

        if (!_verifySignature(message, signature, aggPubkey)) {
            revert InvalidBLSSignature();
        }

        bytes20[] memory pubkeyHashes = new bytes20[](pubkeys.length);
        for (uint256 i = 0; i < pubkeys.length; i++) {
            pubkeyHashes[i] = hashPubkey(pubkeys[i]);
        }

        _batchRegisterValidators(pubkeyHashes, authorizedOperator, maxCommittedGasLimit);
    }

    function _merkleizeRegistrations(BLS12381.G1Point[] calldata pubkeys, BLS12381.G2Point[] calldata signatures,) internal returns (bytes32 registrationRoot) {
        // Create leaves array with padding
        bytes32[] memory leaves = new bytes32[](pubkeys.length);

        // Create leaf nodes by hashing Registration structs
        for (uint256 i = 0; i < pubkeys.length; i++) {
            leaves[i] = keccak256(abi.encode(pubkeys[i], signatures[i]));
        }

        registrationRoot = URCMerkleTree.generateTree(leaves);
    }


    /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
    /// @dev This function allows anyone to register a list of Validators.
    /// @param pubkeyHashes List of BLS public key hashes for the Validators to be registered
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function batchRegisterValidatorsUnsafe(
        bytes20[] calldata pubkeyHashes,
        uint32 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        if (!parameters.ALLOW_UNSAFE_REGISTRATION()) {
            revert UnsafeRegistrationNotAllowed();
        }

        _batchRegisterValidators(pubkeyHashes, authorizedOperator, maxCommittedGasLimit);
    }

    // ========= UPDATE FUNCTIONS =========

    /// @notice Update the maximum gas limit that a validator can commit for preconfirmations
    /// @dev Only the `controller` of the validator can update this value.
    /// @param pubkeyHash The hash of the BLS public key of the validator
    /// @param maxCommittedGasLimit The new maximum gas limit
    function updateMaxCommittedGasLimit(bytes20 pubkeyHash, uint32 maxCommittedGasLimit) public {
        address controller = VALIDATORS.getController(pubkeyHash);
        if (msg.sender != controller) {
            revert UnauthorizedCaller();
        }

        VALIDATORS.updateMaxCommittedGasLimit(pubkeyHash, maxCommittedGasLimit);
    }

    // ========= HELPERS =========

    /// @notice Internal helper to register a single validator
    /// @param pubkeyHash BLS public key hash of the validator
    /// @param authorizedOperator Address of the authorized operator
    /// @param maxCommittedGasLimit Maximum gas limit that the validator can commit for preconfirmations
    function _registerValidator(bytes20 pubkeyHash, address authorizedOperator, uint32 maxCommittedGasLimit) internal {
        if (authorizedOperator == address(0)) {
            revert InvalidAuthorizedOperator();
        }
        if (pubkeyHash == bytes20(0)) {
            revert InvalidPubkey();
        }

        VALIDATORS.insert(
            pubkeyHash,
            maxCommittedGasLimit,
            VALIDATORS.getOrInsertController(msg.sender),
            VALIDATORS.getOrInsertAuthorizedOperator(authorizedOperator)
        );
        emit ValidatorRegistered(pubkeyHash);
    }

    /// @notice Internal helper to register a batch of validators
    /// @param pubkeyHashes List of BLS public key hashes of the validators
    /// @param authorizedOperator Address of the authorized operator
    /// @param maxCommittedGasLimit Maximum gas limit that the validators can commit for preconfirmations
    function _batchRegisterValidators(
        bytes20[] memory pubkeyHashes,
        address authorizedOperator,
        uint32 maxCommittedGasLimit
    ) internal {
        if (authorizedOperator == address(0)) {
            revert InvalidAuthorizedOperator();
        }

        uint32 authorizedOperatorIndex = VALIDATORS.getOrInsertAuthorizedOperator(authorizedOperator);
        uint32 controllerIndex = VALIDATORS.getOrInsertController(msg.sender);
        uint256 pubkeysLength = pubkeyHashes.length;

        for (uint32 i; i < pubkeysLength; i++) {
            bytes20 pubkeyHash = pubkeyHashes[i];

            if (pubkeyHash == bytes20(0)) {
                revert InvalidPubkey();
            }

            VALIDATORS.insert(pubkeyHash, maxCommittedGasLimit, controllerIndex, authorizedOperatorIndex);
            emit ValidatorRegistered(pubkeyHash);
        }
    }

    /// @notice Internal helper to get the ValidatorInfo struct from a _Validator struct
    /// @param _val Validator struct
    /// @return ValidatorInfo struct
    function _getValidatorInfo(
        ValidatorsLib._Validator memory _val
    ) internal view returns (ValidatorInfo memory) {
        return ValidatorInfo({
            pubkeyHash: _val.pubkeyHash,
            maxCommittedGasLimit: _val.maxCommittedGasLimit,
            authorizedOperator: VALIDATORS.getAuthorizedOperator(_val.pubkeyHash),
            controller: VALIDATORS.getController(_val.pubkeyHash)
        });
    }

    /// @notice Helper to compute the hash of a BLS public key
    /// @param pubkey Decompressed BLS public key
    /// @return Hash of the public key in compressed form
    function hashPubkey(
        BLS12381.G1Point memory pubkey
    ) public pure returns (bytes20) {
        uint256[2] memory compressedPubKey = pubkey.compress();
        bytes32 fullHash = keccak256(abi.encodePacked(compressedPubKey));
        // take the leftmost 20 bytes of the keccak256 hash
        return bytes20(uint160(uint256(fullHash)));
    }
}
