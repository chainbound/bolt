// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {MapWithTimeData} from "../lib/MapWithTimeData.sol";
import {IBoltValidators} from "../interfaces/IBoltValidators.sol";
import {IBoltMiddleware} from "../interfaces/IBoltMiddleware.sol";
import {IBoltManager} from "../interfaces/IBoltManager.sol";

import {IStrategyManager} from "@eigenlayer/src/contracts/interfaces/IStrategyManager.sol";
import {IAVSDirectory} from "@eigenlayer/src/contracts/interfaces/IAVSDirectory.sol";
import {IDelegationManager} from "@eigenlayer/src/contracts/interfaces/IDelegationManager.sol";
import {ISignatureUtils} from "@eigenlayer/src/contracts/interfaces/ISignatureUtils.sol";
import {IStrategy} from "@eigenlayer/src/contracts/interfaces/IStrategy.sol";
import {AVSDirectoryStorage} from "@eigenlayer/src/contracts/core/AVSDirectoryStorage.sol";
import {DelegationManagerStorage} from "@eigenlayer/src/contracts/core/DelegationManagerStorage.sol";
import {StrategyManagerStorage} from "@eigenlayer/src/contracts/core/StrategyManagerStorage.sol";

contract BoltEigenLayerMiddleware is IBoltMiddleware, OwnableUpgradeable, UUPSUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;

    // ========= STORAGE =========

    /// @notice Validators registry, where validators are registered via their
    /// BLS pubkey and are assigned a sequence number.
    IBoltManager public boltManager;

    /// @notice Set of EigenLayer protocol strategies that are used in Bolt Protocol.
    EnumerableMap.AddressToUintMap private strategies;

    /// @notice Set of EigenLayer collaterals addresses that are allowed.
    EnumerableSet.AddressSet private whitelistedCollaterals;

    /// @notice Address of the EigenLayer AVS Directory contract.
    AVSDirectoryStorage public AVS_DIRECTORY;

    /// @notice Address of the EigenLayer Delegation Manager contract.
    DelegationManagerStorage public DELEGATION_MANAGER;

    /// @notice Address of the EigenLayer Strategy Manager contract.
    StrategyManagerStorage public STRATEGY_MANAGER;

    /// @notice Start timestamp of the first epoch.
    uint48 public START_TIMESTAMP;

    // ========= CONSTANTS =========

    /// @notice Duration of an epoch in seconds.
    uint48 public constant EPOCH_DURATION = 1 days;

    /// @notice Duration of the slashing window in seconds.
    uint48 public constant SLASHING_WINDOW = 7 days;

    /// @notice Name hash of the restaking protocol for identifying the instance of `IBoltMiddleware`.
    bytes32 public constant NAME_HASH = keccak256("EIGENLAYER");

    // ========= ERRORS =========

    error StrategyNotAllowed();
    error OperatorAlreadyRegisteredToAVS();

    // ========= INITIALIZER & PROXY FUNCTIONALITY ========= //

    /// @notice Constructor for the BoltEigenLayerMiddleware contract.
    /// @param _boltManager The address of the Bolt Manager contract.
    /// @param _eigenlayerAVSDirectory The address of the EigenLayer AVS Directory contract.
    /// @param _eigenlayerDelegationManager The address of the EigenLayer Delegation Manager contract.
    /// @param _eigenlayerStrategyManager The address of the EigenLayer Strategy Manager.
    function initialize(
        address _owner,
        address _boltManager,
        address _eigenlayerAVSDirectory,
        address _eigenlayerDelegationManager,
        address _eigenlayerStrategyManager
    ) public initializer {
        __Ownable_init(_owner);
        boltManager = IBoltManager(_boltManager);
        START_TIMESTAMP = Time.timestamp();

        AVS_DIRECTORY = AVSDirectoryStorage(_eigenlayerAVSDirectory);
        DELEGATION_MANAGER = DelegationManagerStorage(_eigenlayerDelegationManager);
        STRATEGY_MANAGER = StrategyManagerStorage(_eigenlayerStrategyManager);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // ========= VIEW FUNCTIONS =========

    /// @notice Get the start timestamp of an epoch.
    function getEpochStartTs(
        uint48 epoch
    ) public view returns (uint48 timestamp) {
        return START_TIMESTAMP + epoch * EPOCH_DURATION;
    }

    /// @notice Get the epoch at a given timestamp.
    function getEpochAtTs(
        uint48 timestamp
    ) public view returns (uint48 epoch) {
        return (timestamp - START_TIMESTAMP) / EPOCH_DURATION;
    }

    /// @notice Get the current epoch.
    function getCurrentEpoch() public view returns (uint48 epoch) {
        return getEpochAtTs(Time.timestamp());
    }

    /// @notice Get the list of EigenLayer strategies addresses that are allowed.
    /// @return _strategies The list of strategies addresses that are allowed.
    function getWhitelistedCollaterals() public view returns (address[] memory _strategies) {
        return whitelistedCollaterals.values();
    }

    /// @notice Check if an EigenLayer strategy address is allowed.
    /// @param strategy The strategy address to check if it is allowed.
    /// @return true if the strategy address is allowed, false otherwise.
    function isCollateralWhitelisted(
        address strategy
    ) public view returns (bool) {
        return whitelistedCollaterals.contains(strategy);
    }

    // ========= ADMIN FUNCTIONS =========

    /// @notice Add a collateral address to the whitelist.
    /// @param collateral The collateral address to add to the whitelist.
    function addWhitelistedCollateral(
        address collateral
    ) public onlyOwner {
        whitelistedCollaterals.add(collateral);
    }

    /// @notice Remove a collateral address from the whitelist.
    /// @param collateral The collateral address to remove from the whitelist.
    function removeWhitelistedCollateral(
        address collateral
    ) public onlyOwner {
        whitelistedCollaterals.remove(collateral);
    }

    // ========= EIGENLAYER MIDDLEWARE LOGIC =========

    /// @notice Allow an operator to signal opt-in to Bolt Protocol.
    /// @dev This requires calling the EigenLayer AVS Directory contract to register the operator.
    /// EigenLayer internally contains a mapping from `msg.sender` (our AVS contract) to the operator.
    /// The msg.sender of this call will be the operator address.
    function registerOperator(
        string calldata rpc,
        ISignatureUtils.SignatureWithSaltAndExpiry calldata operatorSignature
    ) public {
        if (boltManager.isOperator(msg.sender)) {
            revert AlreadyRegistered();
        }

        if (!DELEGATION_MANAGER.isOperator(msg.sender)) {
            revert NotOperator();
        }

        // Register the operator to the AVS directory for this AVS
        AVS_DIRECTORY.registerOperatorToAVS(msg.sender, operatorSignature);

        // Register the operator in the manager
        boltManager.registerOperator(msg.sender, rpc);
    }

    /// @notice Deregister an EigenLayer layer operator from working in Bolt Protocol.
    /// @dev This requires calling the EigenLayer AVS Directory contract to deregister the operator.
    /// EigenLayer internally contains a mapping from `msg.sender` (our AVS contract) to the operator.
    function deregisterOperator() public {
        if (!boltManager.isOperator(msg.sender)) {
            revert NotRegistered();
        }

        AVS_DIRECTORY.deregisterOperatorFromAVS(msg.sender);

        boltManager.deregisterOperator(msg.sender);
    }

    /// @notice Allow an operator to signal indefinite opt-out from Bolt Protocol.
    /// @dev Pausing activity does not prevent the operator from being slashable for
    /// the current network epoch until the end of the slashing window.
    function pauseOperator() public {
        boltManager.pauseOperator(msg.sender);
    }

    /// @notice Allow a disabled operator to signal opt-in to Bolt Protocol.
    function unpauseOperator() public {
        boltManager.unpauseOperator(msg.sender);
    }

    /// @notice Register a strategy to work in Bolt Protocol.
    /// @param strategy The EigenLayer strategy address
    function registerStrategy(
        address strategy
    ) public {
        if (strategies.contains(strategy)) {
            revert AlreadyRegistered();
        }

        if (!STRATEGY_MANAGER.strategyIsWhitelistedForDeposit(IStrategy(strategy))) {
            revert StrategyNotAllowed();
        }

        if (!isCollateralWhitelisted(address(IStrategy(strategy).underlyingToken()))) {
            revert CollateralNotWhitelisted();
        }

        strategies.add(strategy);
        strategies.enable(strategy);
    }

    /// @notice Allow a strategy to signal indefinite opt-out from Bolt Protocol.
    function pauseStrategy() public {
        if (!strategies.contains(msg.sender)) {
            revert NotRegistered();
        }

        strategies.disable(msg.sender);
    }

    /// @notice Allow a disabled strategy to signal opt-in to Bolt Protocol.
    function unpauseStrategy() public {
        if (!strategies.contains(msg.sender)) {
            revert NotRegistered();
        }

        strategies.enable(msg.sender);
    }

    /// @notice Check if a strategy is currently enabled to work in Bolt Protocol.
    /// @param strategy The strategy address to check the enabled status for.
    /// @return True if the strategy is enabled, false otherwise.
    function isStrategyEnabled(
        address strategy
    ) public view returns (bool) {
        (uint48 enabledTime, uint48 disabledTime) = strategies.getTimes(strategy);
        return enabledTime != 0 && disabledTime == 0;
    }

    /// @notice Get the collaterals and amounts staked by an operator across the supported strategies.
    ///
    /// @param operator The operator address to get the collaterals and amounts staked for.
    /// @return collaterals The collaterals staked by the operator.
    /// @dev Assumes that the operator is registered and enabled.
    function getOperatorCollaterals(
        address operator
    ) public view returns (address[] memory, uint256[] memory) {
        address[] memory collateralTokens = new address[](strategies.length());
        uint256[] memory amounts = new uint256[](strategies.length());

        uint48 epochStartTs = getEpochStartTs(getEpochAtTs(Time.timestamp()));

        IStrategy[] memory strategyImpls = new IStrategy[](strategies.length());

        for (uint256 i = 0; i < strategies.length(); ++i) {
            (address strategy, uint48 enabledTime, uint48 disabledTime) = strategies.atWithTimes(i);

            if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            IStrategy strategyImpl = IStrategy(strategy);

            address collateral = address(strategyImpl.underlyingToken());
            collateralTokens[i] = collateral;

            strategyImpls[i] = strategyImpl;
        }

        // NOTE: order is preserved, which is why we can use the same index for both arrays below
        uint256[] memory shares = DELEGATION_MANAGER.getOperatorShares(operator, strategyImpls);

        for (uint256 i = 0; i < strategyImpls.length; ++i) {
            amounts[i] = strategyImpls[i].sharesToUnderlyingView(shares[i]);
        }

        return (collateralTokens, amounts);
    }

    /// @notice Get the amount of tokens delegated to an operator across the allowed strategies.
    /// @param operator The operator address to get the stake for.
    /// @param collateral The collateral address to get the stake for.
    /// @return amount The amount of tokens delegated to the operator of the specified collateral.
    function getOperatorStake(address operator, address collateral) public view returns (uint256 amount) {
        uint48 timestamp = Time.timestamp();
        return getOperatorStakeAt(operator, collateral, timestamp);
    }

    /// @notice Get the stake of an operator in EigenLayer protocol at a given timestamp.
    /// @param operator The operator address to check the stake for.
    /// @param collateral The collateral address to check the stake for.
    /// @param timestamp The timestamp to check the stake at.
    /// @return amount The stake of the operator at the given timestamp, in collateral token.
    function getOperatorStakeAt(
        address operator,
        address collateral,
        uint48 timestamp
    ) public view returns (uint256 amount) {
        if (timestamp > Time.timestamp() || timestamp < START_TIMESTAMP) {
            revert InvalidQuery();
        }

        uint48 epochStartTs = getEpochStartTs(getEpochAtTs(timestamp));

        // NOTE: Can this be done more gas-efficiently?
        IStrategy[] memory strategyMem = new IStrategy[](1);

        for (uint256 i = 0; i < strategies.length(); i++) {
            (address strategy, uint48 enabledTime, uint48 disabledTime) = strategies.atWithTimes(i);

            if (collateral != address(IStrategy(strategy).underlyingToken())) {
                continue;
            }

            if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            strategyMem[0] = IStrategy(strategy);
            // NOTE: order is preserved i.e., shares[i] corresponds to strategies[i]
            uint256[] memory shares = DELEGATION_MANAGER.getOperatorShares(operator, strategyMem);
            amount += IStrategy(strategy).sharesToUnderlyingView(shares[0]);
        }

        return amount;
    }

    // ========= EIGENLAYER AVS FUNCTIONS =========

    /// @notice emits an `AVSMetadataURIUpdated` event indicating the information has updated.
    /// @param metadataURI The URI for metadata associated with an avs
    function updateAVSMetadataURI(
        string calldata metadataURI
    ) public onlyOwner {
        AVS_DIRECTORY.updateAVSMetadataURI(metadataURI);
    }

    // ========= HELPER FUNCTIONS =========

    /// @notice Check if a map entry was active at a given timestamp.
    /// @param enabledTime The enabled time of the map entry.
    /// @param disabledTime The disabled time of the map entry.
    /// @param timestamp The timestamp to check the map entry status at.
    /// @return True if the map entry was active at the given timestamp, false otherwise.
    function _wasEnabledAt(uint48 enabledTime, uint48 disabledTime, uint48 timestamp) private pure returns (bool) {
        return enabledTime != 0 && enabledTime <= timestamp && (disabledTime == 0 || disabledTime >= timestamp);
    }
}
