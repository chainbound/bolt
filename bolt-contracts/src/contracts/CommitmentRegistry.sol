// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// TODO: switch back to the real library when the precompile is testable
import {BLS12381} from "../lib/BLS12381_Mocked.sol";
import {BeaconChainUtils} from "../lib/BeaconChainUtils.sol";

/// @title Commitment Registry prototype
/// @dev R&D and specs available at <https://github.com/chainbound/bolt/discussions/95>
contract CommitmentRegistry {
    using BLS12381 for BLS12381.G1Point;

    /// @notice Collateral Providers
    /// @dev Collateral Providers are entities that have staked collateral to back
    /// the commitments made by Validators. They are identified by their EOA.
    /// Each Validator can have only one Collateral Provider at a time.
    ///
    /// Collateral Deposits and Withdrawals are tracked for each Collateral Provider
    /// and can be used to deterministically calculate the collateral at stake at any
    /// given time for any Validator.
    mapping(address => CollateralProvider) public COLLATERAL_PROVIDERS;

    /// @notice Live collateral at stake for each Collateral Provider
    /// @dev Mapping from Collateral Provider EOA to asset address to amount at stake
    mapping(address => mapping(address => uint256)) public collateralProviderLiveCollateralAmounts;

    /// @notice Collateral Deposit history for each Collateral Provider
    mapping(address => CollateralDeposit[]) public collateralProviderDepositHistory;

    /// @notice Collateral Withdrawal history for each Collateral Provider
    mapping(address => CollateralWithdrawal[]) public collateralProviderWithdrawalHistory;

    /// @notice Collateral Provider
    struct CollateralProvider {
        uint64 validatorsCount;
        bool exists;
    }

    /// @notice Collateral at stake
    struct Collateral {
        address asset;
        uint256 amount;
    }

    /// @notice Collateral Deposit
    struct CollateralDeposit {
        Collateral collateral;
        uint256 timestamp;
    }

    /// @notice Collateral Withdrawal
    struct CollateralWithdrawal {
        Collateral collateral;
        uint256 timestamp;
    }

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
    uint64 internal nextValidatorSequenceNumber;

    /// @notice Validator
    struct Validator {
        uint64 sequenceNumber;
        address collateralProvider;
        address operator;
        bool exists;
    }

    /// @notice Operators (aka Committment creators)
    /// @dev Operators are entities that have been authorized to make credible
    /// commitments on some Validator's behalf. To become an Operator, it is
    /// necessary to obtain authorization from the Collateral Provider EOA that
    /// deposited collateral for that Validator.
    ///
    /// Operators are identified by their commitment signing key, which is an EOA.
    /// Each Validator can authorize an Operator, and each Operator can be responsible
    /// for multiple Validators at the same time.
    ///
    /// NOTE: Operators have the potential to get the Collateral Provider slashed if they
    /// make invalid commitments on behalf of the Validator they are responsible for.
    mapping(address => Operator) OPERATORS;

    /// @notice Operator
    struct Operator {
        string rpcEndpoint;
        string extraData;
        bool exists;
    }

    /// @notice Constructor
    /// @dev Initializes the Commitment Registry contract
    constructor() {}

    /// @notice Register a Collateral Provider
    /// @dev This function allows anyone to register a Collateral Provider EOA
    /// in the registry, which is responsible for depositing collateral for any Validators
    /// that authorize it to do so.
    function registerCollateralProvider() public {
        require(!COLLATERAL_PROVIDERS[msg.sender].exists, "Collateral Provider already exists");

        COLLATERAL_PROVIDERS[msg.sender] = CollateralProvider(0, true);
    }

    /// @notice Register an Operator
    /// @dev This function allows anyone to register an Operator EOA in the registry,
    /// which is responsible for making credible commitments on behalf of any Validators
    /// that authorize it to do so.
    /// @param rpcEndpoint URL of the RPC endpoint where the Operator can be reached
    /// @param extraData Additional data that the Operator may want to provide
    function registerOperator(string calldata rpcEndpoint, string calldata extraData) public {
        require(!OPERATORS[msg.sender].exists, "Operator already exists");

        OPERATORS[msg.sender] = Operator(rpcEndpoint, extraData, true);
    }

    /// @notice Update the data for an Operator
    /// @dev This function allows an Operator to update its RPC endpoint and extra data.
    /// @param rpcEndpoint URL of the RPC endpoint where the Operator can be reached
    /// @param extraData Additional data that the Operator may want to provide
    function updateOperatorData(string calldata rpcEndpoint, string calldata extraData) public {
        require(OPERATORS[msg.sender].exists, "Operator not found");

        OPERATORS[msg.sender] = Operator(rpcEndpoint, extraData, true);
    }

    /// @notice Deposit collateral for all Validators under the Collateral Provider
    /// @dev This function allows an existing CollateralProvider EOA to deposit collateral
    /// for all the Validators that are under its responsibility.
    /// @param asset Address of the asset to be deposited
    /// @param amount Amount of the asset to be deposited
    function depositCollateral(address asset, uint256 amount) public {
        CollateralProvider storage provider = COLLATERAL_PROVIDERS[msg.sender];
        require(provider.exists, "Collateral Provider does not exist");

        // Update the live collateral at stake for the Collateral Provider
        collateralProviderLiveCollateralAmounts[msg.sender][asset] += amount;

        // Add the deposit to the history
        collateralProviderDepositHistory[msg.sender].push(CollateralDeposit(Collateral(asset, amount), block.timestamp));
    }

    // TODO: add a mechanism to withdraw collateral safely

    /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
    /// @dev This function allows anyone to register a list of Validators, authorize a Collateral Provider
    /// to later deposit collateral for them, and authorize an Operator to start making credible commitments.
    /// The Collateral Provider and Operator addresses must exist in the registry before calling this function.
    /// @param pubkeys List of BLS public keys for the Validators to be registered
    /// @param signature BLS aggregated signature of the registration message for this batch of Validators
    /// @param collateralProvider EOA of the Collateral Provider that will be authorized
    /// @param operator EOA of the Operator that will be authorized
    function batchRegisterValidators(
        BLS12381.G1Point[] calldata pubkeys,
        BLS12381.G2Point calldata signature,
        address collateralProvider,
        address operator
    ) public {
        require(COLLATERAL_PROVIDERS[collateralProvider].exists, "Collateral Provider does not exist");
        require(OPERATORS[operator].exists, "Operator does not exist");

        uint256 validatorsCount = pubkeys.length;
        uint64[] memory expectedValidatorSequenceNumbers = new uint64[](validatorsCount);
        for (uint256 i = 0; i < validatorsCount; i++) {
            expectedValidatorSequenceNumbers[i] = nextValidatorSequenceNumber + uint64(i);
        }

        // Reconstruct the unique message for which we expect an aggregated signature.
        // NOTE: we need the msg.sender to prevent a front-running attack by an EOA that may
        // try to register the same validators with a different Collateral Provider / Operator
        bytes memory message = abi.encodePacked(block.chainid, msg.sender, expectedValidatorSequenceNumbers);

        // Verify the aggregated signature once for all pubkeys
        require(_verifyAggregatedBLSSignature(pubkeys, signature, message), "Invalid signature");

        // Register the validators and authorize the Collateral Provider and Operator for them
        for (uint256 i = 0; i < validatorsCount; i++) {
            // TODO: Verify the existence of each validator in the Beacon Chain (through EIP-4788)
            // TODO: calculate the calldata size and cost for each of these calls
            // bytes32 beaconBlockRoot = BeaconChainUtils._getLatestBeaconBlockRoot();
            // require(
            //     ValidatorVerifier._proveValidator(validatorProof, validatorSSZ, validatorIndex, beaconBlockRoot),
            //     "Validator does not exist on the Beacon Chain"
            // );

            bytes32 pubKeyHash = _pubkeyHash(pubkeys[i]);
            require(!VALIDATORS[pubKeyHash].exists, "Validator already exists");
            VALIDATORS[pubKeyHash] = Validator(nextValidatorSequenceNumber, collateralProvider, operator, true);
        }

        nextValidatorSequenceNumber += uint64(validatorsCount);
        COLLATERAL_PROVIDERS[collateralProvider].validatorsCount += uint64(validatorsCount);
    }

    /// @notice Get the collateral at stake for a Validator for a specific asset
    /// @param pubkey BLS public key of the Validator
    /// @param asset Address of the asset to check the collateral for
    /// @return The amount of collateral at stake for the Validator
    function getValidatorStakeAmount(BLS12381.G1Point calldata pubkey, address asset) public view returns (uint256) {
        Validator memory validator = VALIDATORS[_pubkeyHash(pubkey)];
        require(validator.exists, "Validator does not exist");

        // Invariant: the Validator must have a Collateral Provider assigned
        return collateralProviderLiveCollateralAmounts[validator.collateralProvider][asset];
    }

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
    }

    /// @notice Compute the hash of a BLS public key
    /// @param pubkey BLS public key
    /// @return Hash of the public key in compressed form
    function _pubkeyHash(BLS12381.G1Point memory pubkey) internal pure returns (bytes32) {
        uint256[2] memory compressedPubKey = pubkey.compress();
        return keccak256(abi.encodePacked(compressedPubKey));
    }
}
