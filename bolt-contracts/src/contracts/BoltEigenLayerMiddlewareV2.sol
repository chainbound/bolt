// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {MapWithTimeData} from "../lib/MapWithTimeData.sol";
import {IBoltParametersV1} from "../interfaces/IBoltParametersV1.sol";
import {IBoltMiddlewareV1} from "../interfaces/IBoltMiddlewareV1.sol";
import {IBoltManagerV1} from "../interfaces/IBoltManagerV1.sol";

import {IServiceManager} from "@eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import {IStrategyManager} from "@eigenlayer/src/contracts/interfaces/IStrategyManager.sol";
import {IAVSDirectory} from "@eigenlayer/src/contracts/interfaces/IAVSDirectory.sol";
import {IDelegationManager} from "@eigenlayer/src/contracts/interfaces/IDelegationManager.sol";
import {ISignatureUtils} from "@eigenlayer/src/contracts/interfaces/ISignatureUtils.sol";
import {IStrategy} from "@eigenlayer/src/contracts/interfaces/IStrategy.sol";
import {AVSDirectoryStorage} from "@eigenlayer/src/contracts/core/AVSDirectoryStorage.sol";
import {DelegationManagerStorage} from "@eigenlayer/src/contracts/core/DelegationManagerStorage.sol";
import {StrategyManagerStorage} from "@eigenlayer/src/contracts/core/StrategyManagerStorage.sol";

/// @title Bolt EigenLayer Middleware contract.
/// @notice This contract is responsible for interfacing with the EigenLayer restaking protocol.
/// @dev This contract is upgradeable using the UUPSProxy pattern. Storage layout remains fixed across upgrades
/// with the use of storage gaps.
/// See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
/// To validate the storage layout, use the Openzeppelin Foundry Upgrades toolkit.
/// You can also validate manually with forge: forge inspect <contract> storage-layout --pretty
contract BoltEigenLayerMiddlewareV2 is IBoltMiddlewareV1, IServiceManager, OwnableUpgradeable, UUPSUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;

    // ========= STORAGE =========

    /// @notice Start timestamp of the first epoch.
    uint48 public START_TIMESTAMP;

    /// @notice Bolt Parameters contract.
    IBoltParametersV1 public parameters;

    /// @notice Validators registry, where validators are registered via their
    /// BLS pubkey and are assigned a sequence number.
    IBoltManagerV1 public manager;

    /// @notice Set of EigenLayer protocol strategies that are used in Bolt Protocol.
    EnumerableMap.AddressToUintMap private strategies;

    /// @notice Address of the EigenLayer AVS Directory contract.
    IAVSDirectory public AVS_DIRECTORY;

    /// @notice Address of the EigenLayer Delegation Manager contract.
    DelegationManagerStorage public DELEGATION_MANAGER;

    /// @notice Address of the EigenLayer Strategy Manager contract.
    StrategyManagerStorage public STRATEGY_MANAGER;

    /// @notice Name hash of the restaking protocol for identifying the instance of `IBoltMiddleware`.
    bytes32 public NAME_HASH;

    // --> Storage layout marker: 9 slots

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     * This can be validated with the Openzeppelin Foundry Upgrades toolkit.
     *
     * Total storage slots: 50
     */
    uint256[41] private __gap;

    // ========= ERRORS =========

    error StrategyNotAllowed();
    error OperatorAlreadyRegisteredToAVS();

    // ========= INITIALIZER & PROXY FUNCTIONALITY ========= //

    /// @notice Constructor for the BoltEigenLayerMiddleware contract.
    /// @param _parameters The address of the Bolt Parameters contract.
    /// @param _manager The address of the Bolt Manager contract.
    /// @param _eigenlayerAVSDirectory The address of the EigenLayer AVS Directory contract.
    /// @param _eigenlayerDelegationManager The address of the EigenLayer Delegation Manager contract.
    /// @param _eigenlayerStrategyManager The address of the EigenLayer Strategy Manager.
    function initialize(
        address _owner,
        address _parameters,
        address _manager,
        address _eigenlayerAVSDirectory,
        address _eigenlayerDelegationManager,
        address _eigenlayerStrategyManager
    ) public initializer {
        __Ownable_init(_owner);
        parameters = IBoltParametersV1(_parameters);
        manager = IBoltManagerV1(_manager);
        START_TIMESTAMP = Time.timestamp();

        AVS_DIRECTORY = IAVSDirectory(_eigenlayerAVSDirectory);
        DELEGATION_MANAGER = DelegationManagerStorage(_eigenlayerDelegationManager);
        STRATEGY_MANAGER = StrategyManagerStorage(_eigenlayerStrategyManager);
        NAME_HASH = keccak256("EIGENLAYER");
    }

    function initializeV2(
        address _owner,
        address _parameters,
        address _manager,
        address _eigenlayerAVSDirectory,
        address _eigenlayerDelegationManager,
        address _eigenlayerStrategyManager
    ) public reinitializer(2) {
        __Ownable_init(_owner);
        parameters = IBoltParametersV1(_parameters);
        manager = IBoltManagerV1(_manager);
        START_TIMESTAMP = Time.timestamp();

        AVS_DIRECTORY = IAVSDirectory(_eigenlayerAVSDirectory);
        DELEGATION_MANAGER = DelegationManagerStorage(_eigenlayerDelegationManager);
        STRATEGY_MANAGER = StrategyManagerStorage(_eigenlayerStrategyManager);
        NAME_HASH = keccak256("EIGENLAYER");
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // ========= VIEW FUNCTIONS =========

    /// @notice Get the start timestamp of an epoch.
    function getEpochStartTs(
        uint48 epoch
    ) public view returns (uint48 timestamp) {
        return START_TIMESTAMP + epoch * parameters.EPOCH_DURATION();
    }

    /// @notice Get the epoch at a given timestamp.
    function getEpochAtTs(
        uint48 timestamp
    ) public view returns (uint48 epoch) {
        return (timestamp - START_TIMESTAMP) / parameters.EPOCH_DURATION();
    }

    /// @notice Get the current epoch.
    function getCurrentEpoch() public view returns (uint48 epoch) {
        return getEpochAtTs(Time.timestamp());
    }

    function getWhitelistedStrategies() public view returns (address[] memory) {
        return strategies.keys();
    }

    // ========= ADMIN FUNCTIONS =========
    /// @notice Register a strategy to work in Bolt Protocol.
    /// @param strategy The EigenLayer strategy address
    function registerStrategy(
        address strategy
    ) public onlyOwner {
        if (strategies.contains(strategy)) {
            revert AlreadyRegistered();
        }

        if (!STRATEGY_MANAGER.strategyIsWhitelistedForDeposit(IStrategy(strategy))) {
            revert StrategyNotAllowed();
        }

        strategies.add(strategy);
        strategies.enable(strategy);
    }

    /// @notice Deregister a strategy from working in Bolt Protocol.
    /// @param strategy The EigenLayer strategy address.
    function deregisterStrategy(
        address strategy
    ) public onlyOwner {
        if (!strategies.contains(strategy)) {
            revert NotRegistered();
        }

        strategies.remove(strategy);
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
        if (manager.isOperator(msg.sender)) {
            revert AlreadyRegistered();
        }

        if (!DELEGATION_MANAGER.isOperator(msg.sender)) {
            revert NotOperator();
        }

        registerOperatorToAVS(msg.sender, operatorSignature);

        // Register the operator in the manager
        manager.registerOperator(msg.sender, rpc);
    }

    /// @notice Deregister an EigenLayer operator from working in Bolt Protocol.
    /// @dev This requires calling the EigenLayer AVS Directory contract to deregister the operator.
    /// EigenLayer internally contains a mapping from `msg.sender` (our AVS contract) to the operator.
    function deregisterOperator() public {
        if (!manager.isOperator(msg.sender)) {
            revert NotRegistered();
        }

        deregisterOperatorFromAVS(msg.sender);

        manager.deregisterOperator(msg.sender);
    }

    /// @notice Allow an operator to signal indefinite opt-out from Bolt Protocol.
    /// @dev Pausing activity does not prevent the operator from being slashable for
    /// the current network epoch until the end of the slashing window.
    function pauseOperator() public {
        manager.pauseOperator(msg.sender);
    }

    /// @notice Allow a disabled operator to signal opt-in to Bolt Protocol.
    function unpauseOperator() public {
        manager.unpauseOperator(msg.sender);
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

        for (uint256 i = 0; i < strategies.length(); ++i) {
            (address strategy, uint48 enabledTime, uint48 disabledTime) = strategies.atWithTimes(i);

            if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            IStrategy strategyImpl = IStrategy(strategy);

            address collateral = address(strategyImpl.underlyingToken());
            collateralTokens[i] = collateral;

            uint256 shares = DELEGATION_MANAGER.operatorShares(operator, strategyImpl);
            amounts[i] = strategyImpl.sharesToUnderlyingView(shares);
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

        for (uint256 i = 0; i < strategies.length(); i++) {
            (address strategy, uint48 enabledTime, uint48 disabledTime) = strategies.atWithTimes(i);

            if (collateral != address(IStrategy(strategy).underlyingToken())) {
                continue;
            }

            if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            uint256 shares = DELEGATION_MANAGER.operatorShares(operator, IStrategy(strategy));
            amount += IStrategy(strategy).sharesToUnderlyingView(shares);
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

    // ============== EIGENLAYER SERVICE MANAGER ================= //
    // Cfr. https://docs.eigenlayer.xyz/developers/avs-dashboard-onboarding
    // getOperatorRestakedStrategies and getRestakeableStrategies have reference implementations
    // that read from RegistryCoordinator & StakeRegistry. These are middleware contracts that
    // are not used in the EigenLayer operator CLI as of today (23 Oct 2024): https://github.com/Layr-Labs/eigensdk-go/blob/0042b1a0dd502bb03c6bf1da85fc096c5c8e8f1b/chainio/clients/elcontracts/writer.go#L158
    //
    // So we'll just get that information from our own system for now.

    function registerOperatorToAVS(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) public override {
        // Register the operator to the AVS directory for this AVS
        AVS_DIRECTORY.registerOperatorToAVS(operator, operatorSignature);
    }

    function deregisterOperatorFromAVS(
        address operator
    ) public override {
        // NOTE: need to do this check because these functions have to be public
        if (msg.sender != operator) {
            revert NotAllowed();
        }

        AVS_DIRECTORY.deregisterOperatorFromAVS(operator);
    }

    function getOperatorRestakedStrategies(
        address operator
    ) external view override returns (address[] memory) {
        address[] memory restakedStrategies = new address[](strategies.length());

        uint48 epochStartTs = getEpochStartTs(getEpochAtTs(Time.timestamp()));

        for (uint256 i = 0; i < strategies.length(); ++i) {
            (address strategy, uint48 enabledTime, uint48 disabledTime) = strategies.atWithTimes(i);

            if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            if (DELEGATION_MANAGER.operatorShares(operator, IStrategy(strategy)) > 0) {
                restakedStrategies[restakedStrategies.length] = strategy;
            }
        }

        return restakedStrategies;
    }

    function getRestakeableStrategies() external view override returns (address[] memory) {
        return strategies.keys();
    }

    function avsDirectory() external view override returns (address) {
        return address(AVS_DIRECTORY);
    }
}
