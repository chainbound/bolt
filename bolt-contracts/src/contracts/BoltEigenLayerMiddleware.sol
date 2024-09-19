// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {Time} from "lib/openzeppelin-contracts/contracts/utils/types/Time.sol";
import {EnumerableMap} from "lib/openzeppelin-contracts/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

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

contract BoltEigenLayerMiddleware is IBoltMiddleware, Ownable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;

    error StrategyNotAllowed();
    error OperatorNotRegisteredToAVS();

    // ========= STORAGE =========

    /// @notice Validators registry, where validators are registered via their
    /// BLS pubkey and are assigned a sequence number.
    IBoltValidators public validators;

    /// @notice Set of EigenLayer operators addresses that have opted in to Bolt Protocol.
    EnumerableMap.AddressToUintMap private operators;

    /// @notice Set of EigenLayer protocol strategies that are used in Bolt Protocol.
    EnumerableMap.AddressToUintMap private strategies;

    /// @notice Set of EigenLayer collaterals addresses that are allowed.
    EnumerableSet.AddressSet private whitelistedCollaterals;

    // ========= IMMUTABLES =========

    /// @notice Address of the EigenLayer AVS Directory contract.
    AVSDirectoryStorage public immutable AVS_DIRECTORY;

    /// @notice Address of the EigenLayer Delegation Manager contract.
    DelegationManagerStorage public immutable DELEGATION_MANAGER;

    /// @notice Address of the EigenLayer Strategy Manager contract.
    StrategyManagerStorage public immutable STRATEGY_MANAGER;

    /// @notice Start timestamp of the first epoch.
    uint48 public immutable START_TIMESTAMP;

    // ========= CONSTANTS =========

    /// @notice Slasher that can instantly slash operators without veto.
    uint256 public constant INSTANT_SLASHER_TYPE = 0;

    /// @notice Slasher that can request a veto before actually slashing operators.
    uint256 public constant VETO_SLASHER_TYPE = 1;

    /// @notice Duration of an epoch in seconds.
    uint48 public constant EPOCH_DURATION = 1 days;

    /// @notice Duration of the slashing window in seconds.
    uint48 public constant SLASHING_WINDOW = 7 days;

    // ========= CONSTRUCTOR =========

    /// @notice Constructor for the BoltManager contract.
    /// @param _validators The address of the validators registry.
    constructor(
        address _owner,
        address _validators,
        address _eigenlayerAVSDirectory,
        address _eigenlayerDelegationManager,
        address _eigenlayerStrategyManager
    ) Ownable(_owner) {
        validators = IBoltValidators(_validators);
        START_TIMESTAMP = Time.timestamp();

        AVS_DIRECTORY = AVSDirectoryStorage(_eigenlayerAVSDirectory);
        DELEGATION_MANAGER = DelegationManagerStorage(_eigenlayerDelegationManager);
        STRATEGY_MANAGER = StrategyManagerStorage(_eigenlayerStrategyManager);
    }

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

    /// @notice Check if an operator address is authorized to work for a validator,
    /// given the validator's pubkey hash. This function performs a lookup in the
    /// validators registry to check if they explicitly authorized the operator.
    /// @param operator The operator address to check the authorization for.
    /// @param pubkeyHash The pubkey hash of the validator to check the authorization for.
    /// @return True if the operator is authorized, false otherwise.
    function isOperatorAuthorizedForValidator(address operator, bytes32 pubkeyHash) public view returns (bool) {
        if (operator == address(0) || pubkeyHash == bytes32(0)) {
            revert InvalidQuery();
        }

        return validators.getValidatorByPubkeyHash(pubkeyHash).authorizedOperator == operator;
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
    /// @param operator The operator address to signal opt-in for.
    function registerOperator(
        address operator
    ) public {
        if (operators.contains(operator)) {
            revert AlreadyRegistered();
        }

        if (!DELEGATION_MANAGER.isOperator(operator)) {
            revert NotOperator();
        }

        if (!checkIfOperatorRegisteredToAVS(operator)) {
            revert OperatorNotRegisteredToAVS();
        }

        operators.add(operator);
        operators.enable(operator);
    }

    /// @notice Allow an operator to signal indefinite opt-out from Bolt Protocol.
    /// @dev Pausing activity does not prevent the operator from being slashable for
    /// the current network epoch until the end of the slashing window.
    function pauseOperator() public {
        if (!operators.contains(msg.sender)) {
            revert NotRegistered();
        }

        operators.disable(msg.sender);
    }

    /// @notice Allow a disabled operator to signal opt-in to Bolt Protocol.
    function unpauseOperator() public {
        if (!operators.contains(msg.sender)) {
            revert NotRegistered();
        }

        operators.enable(msg.sender);
    }

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

    /// @notice Check if an operator is currently enabled to work in Bolt Protocol.
    /// @param operator The operator address to check the enabled status for.
    /// @return True if the operator is enabled, false otherwise.
    function isOperatorEnabled(
        address operator
    ) public view returns (bool) {
        (uint48 enabledTime, uint48 disabledTime) = operators.getTimes(operator);
        return enabledTime != 0 && disabledTime == 0;
    }

    /// @notice Get the status of multiple proposers, given their pubkey hashes.
    /// @param pubkeyHashes The pubkey hashes of the proposers to get the status for.
    /// @return statuses The statuses of the proposers, including their operator and active stake.
    function getProposersStatus(
        bytes32[] memory pubkeyHashes
    ) public view returns (IBoltManager.ProposerStatus[] memory statuses) {
        statuses = new IBoltManager.ProposerStatus[](pubkeyHashes.length);
        for (uint256 i = 0; i < pubkeyHashes.length; ++i) {
            statuses[i] = getProposerStatus(pubkeyHashes[i]);
        }
    }

    /// @notice Get the status of a proposer, given their pubkey hash.
    /// @param pubkeyHash The pubkey hash of the proposer to get the status for.
    /// @return status The status of the proposer, including their operator and active stake.
    function getProposerStatus(
        bytes32 pubkeyHash
    ) public view returns (IBoltManager.ProposerStatus memory status) {
        if (pubkeyHash == bytes32(0)) {
            revert InvalidQuery();
        }

        uint48 epochStartTs = getEpochStartTs(getEpochAtTs(Time.timestamp()));
        IBoltValidators.Validator memory validator = validators.getValidatorByPubkeyHash(pubkeyHash);

        address operator = validator.authorizedOperator;

        status.pubkeyHash = pubkeyHash;
        status.active = validator.exists;
        status.operator = operator;

        (uint48 enabledTime, uint48 disabledTime) = operators.getTimes(operator);
        if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
            return status;
        }

        status.collaterals = new address[](strategies.length());
        status.amounts = new uint256[](strategies.length());

        for (uint256 i = 0; i < strategies.length(); ++i) {
            (address strategy, uint48 enabledVaultTime, uint48 disabledVaultTime) = strategies.atWithTimes(i);

            address collateral = address(IStrategy(strategy).underlyingToken());
            status.collaterals[i] = collateral;
            if (!_wasEnabledAt(enabledVaultTime, disabledVaultTime, epochStartTs)) {
                continue;
            }

            status.amounts[i] = getOperatorStake(operator, collateral);
        }
    }

    /// @notice Get the amount of tokens delegated to an operator across the allowed strategies.
    //  @param operator The operator address to get the stake for.
    //  @param strategies The list of strategies to get the stake for.
    //  @return tokenAmounts The amount of tokens delegated to the operator for each strategy.
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

    /// @notice Get the total stake of all EigenLayer operators at a given epoch for a collateral asset.
    /// @param epoch The epoch to check the total stake for.
    /// @param collateral The collateral address to check the total stake for.
    /// @return totalStake The total stake of all operators at the given epoch, in collateral token.
    function getTotalStake(uint48 epoch, address collateral) public view returns (uint256 totalStake) {
        uint48 epochStartTs = getEpochStartTs(epoch);

        // for epoch older than SLASHING_WINDOW total stake can be invalidated
        // NOTE: not available in EigenLayer yet since slashing is not live
        // if (
        //     epochStartTs < SLASHING_WINDOW ||
        //     epochStartTs < Time.timestamp() - SLASHING_WINDOW ||
        //     epochStartTs > Time.timestamp()
        // ) {
        //     revert InvalidQuery();
        // }

        for (uint256 i; i < operators.length(); ++i) {
            (address operator, uint48 enabledTime, uint48 disabledTime) = operators.atWithTimes(i);

            // just skip operator if it was added after the target epoch or paused
            if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            totalStake += getOperatorStake(operator, collateral);
        }
    }

    // ========= EIGENLAYER AVS FUNCTIONS =========

    /// @notice Register an EigenLayer layer operator to work in Bolt Protocol.
    /// @dev This requires calling the EigenLayer AVS Directory contract to register the operator.
    /// EigenLayer internally contains a mapping from `msg.sender` (our AVS contract) to the operator
    function registerOperatorToAVS(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) public {
        AVS_DIRECTORY.registerOperatorToAVS(operator, operatorSignature);
    }

    function checkIfOperatorRegisteredToAVS(
        address operator
    ) public view returns (bool registered) {
        return AVS_DIRECTORY.avsOperatorStatus(address(this), operator)
            == IAVSDirectory.OperatorAVSRegistrationStatus.REGISTERED;
    }

    /// @notice Deregister an EigenLayer layer operator from working in Bolt Protocol.
    /// @dev This requires calling the EigenLayer AVS Directory contract to deregister the operator.
    /// EigenLayer internally contains a mapping from `msg.sender` (our AVS contract) to the operator.
    function deregisterOperatorFromAVS() public {
        AVS_DIRECTORY.deregisterOperatorFromAVS(msg.sender);
    }

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
