//
// WARNING: DEPRECATED
// Keeping around for reference but will be removed soon.
//

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {BLS12381} from "../lib/BLS12381.sol";
import {IBoltValidators} from "../interfaces/IBoltValidators.sol";

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

    /// @notice Bolt Validators contract
    IBoltValidators public boltValidators;

    /// @notice Constructor
    /// @dev Initializes the Commitment Registry contract
    /// @param _boltValidators Address of the Bolt Validators contract
    constructor(address _boltValidators) {
        boltValidators = IBoltValidators(_boltValidators);
    }

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

    /// @notice Get the collateral at stake for a Validator for a specific asset
    /// @param pubkey BLS public key of the Validator
    /// @param asset Address of the asset to check the collateral for
    /// @return The amount of collateral at stake for the Validator
    function getValidatorStakeAmount(BLS12381.G1Point calldata pubkey, address asset) public view returns (uint256) {
        IBoltValidators.Validator memory validator = boltValidators.getValidatorByPubkey(pubkey);
        require(validator.exists, "Validator does not exist");

        // Invariant: the Validator must have a Collateral Provider assigned
        return collateralProviderLiveCollateralAmounts[validator.authorizedCollateralProvider][asset];
    }
}
