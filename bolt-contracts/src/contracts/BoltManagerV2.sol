// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {OperatorMapWithTimeV2} from "../lib/OperatorMapWithTimeV2.sol";
import {EnumerableMapV2} from "../lib/EnumerableMapV2.sol";
import {IBoltParametersV1} from "../interfaces/IBoltParametersV1.sol";
import {IBoltMiddlewareV1} from "../interfaces/IBoltMiddlewareV1.sol";
import {IBoltValidatorsV2} from "../interfaces/IBoltValidatorsV2.sol";
import {IBoltManagerV2} from "../interfaces/IBoltManagerV2.sol";

/// @title Bolt Manager
/// @notice The Bolt Manager contract is responsible for managing operators & restaking middlewares, and is the
/// entrypoint contract for all Bolt-related queries for off-chain consumers.
/// @dev This contract is upgradeable using the UUPSProxy pattern. Storage layout remains fixed across upgrades
/// with the use of storage gaps.
/// See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
/// To validate the storage layout, use the Openzeppelin Foundry Upgrades toolkit.
/// You can also validate manually with forge: forge inspect <contract> storage-layout --pretty
contract BoltManagerV2 is IBoltManagerV2, OwnableUpgradeable, UUPSUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMapV2 for EnumerableMapV2.OperatorMap;
    using OperatorMapWithTimeV2 for EnumerableMapV2.OperatorMap;

    // ========= STORAGE =========
    /// @notice Start timestamp of the first epoch.
    uint48 public START_TIMESTAMP;

    /// @notice Bolt Parameters contract.
    IBoltParametersV1 public parameters;

    /// @notice Validators registry, where validators are registered via their
    /// BLS pubkey and are assigned a sequence number.
    IBoltValidatorsV2 public validators;

    /// @notice Set of operator addresses that have opted in to Bolt Protocol.
    EnumerableMapV2.OperatorMap private operators;

    /// @notice Set of restaking protocols supported. Each address corresponds to the
    /// associated Bolt Middleware contract.
    EnumerableSet.AddressSet private restakingProtocols;

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

    modifier onlyMiddleware() {
        if (!restakingProtocols.contains(msg.sender)) {
            revert UnauthorizedMiddleware();
        }
        _;
    }

    // ========= INITIALIZER & PROXY FUNCTIONALITY ========== //

    /// @notice The initializer for the BoltManager contract.
    /// @param _validators The address of the validators registry.
    function initialize(address _owner, address _parameters, address _validators) public initializer {
        __Ownable_init(_owner);

        parameters = IBoltParametersV1(_parameters);
        validators = IBoltValidatorsV2(_validators);

        START_TIMESTAMP = Time.timestamp();
    }

    function initializeV2(address _owner, address _parameters, address _validators) public reinitializer(2) {
        __Ownable_init(_owner);

        parameters = IBoltParametersV1(_parameters);
        validators = IBoltValidatorsV2(_validators);

        START_TIMESTAMP = Time.timestamp();
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // ========= VIEW FUNCTIONS =========

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

    /// @notice Check if an operator address is authorized to work for a validator,
    /// given the validator's pubkey hash. This function performs a lookup in the
    /// validators registry to check if they explicitly authorized the operator.
    /// @param operator The operator address to check the authorization for.
    /// @param pubkeyHash The pubkey hash of the validator to check the authorization for.
    /// @return True if the operator is authorized, false otherwise.
    function isOperatorAuthorizedForValidator(address operator, bytes20 pubkeyHash) public view returns (bool) {
        if (operator == address(0) || pubkeyHash == bytes20(0)) {
            revert InvalidQuery();
        }

        return validators.getValidatorByPubkeyHash(pubkeyHash).authorizedOperator == operator;
    }

    /// @notice Returns the addresses of the middleware contracts of restaking protocols supported by Bolt.
    function getSupportedRestakingProtocols() public view returns (address[] memory middlewares) {
        return restakingProtocols.values();
    }

    /// @notice Returns whether an operator is registered with Bolt.
    function isOperator(
        address operator
    ) public view returns (bool) {
        return operators.contains(operator);
    }

    /// @notice Get the status of multiple proposers, given their pubkey hashes.
    /// @param pubkeyHashes The pubkey hashes of the proposers to get the status for.
    /// @return statuses The statuses of the proposers, including their operator and active stake.
    function getProposerStatuses(
        bytes20[] calldata pubkeyHashes
    ) public view returns (ProposerStatus[] memory statuses) {
        statuses = new ProposerStatus[](pubkeyHashes.length);
        for (uint256 i = 0; i < pubkeyHashes.length; ++i) {
            statuses[i] = getProposerStatus(pubkeyHashes[i]);
        }
    }

    /// @notice Get the status of a proposer, given their pubkey hash.
    /// @param pubkeyHash The pubkey hash of the proposer to get the status for.
    /// @return status The status of the proposer, including their operator and active stake.
    function getProposerStatus(
        bytes20 pubkeyHash
    ) public view returns (ProposerStatus memory status) {
        if (pubkeyHash == bytes20(0)) {
            revert InvalidQuery();
        }

        uint48 epochStartTs = getEpochStartTs(getEpochAtTs(Time.timestamp()));
        // NOTE: this will revert when the proposer does not exist.
        IBoltValidatorsV2.ValidatorInfo memory validator = validators.getValidatorByPubkeyHash(pubkeyHash);

        EnumerableMapV2.Operator memory operatorData = operators.get(validator.authorizedOperator);

        status.pubkeyHash = pubkeyHash;
        status.operator = validator.authorizedOperator;
        status.operatorRPC = operatorData.rpc;

        (uint48 enabledTime, uint48 disabledTime) = operators.getTimes(validator.authorizedOperator);
        if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
            return status;
        }

        (status.collaterals, status.amounts) =
            IBoltMiddlewareV1(operatorData.middleware).getOperatorCollaterals(validator.authorizedOperator);

        // NOTE: check if the sum of the collaterals covers the minimum operator stake required.

        uint256 totalOperatorStake = 0;
        for (uint256 i = 0; i < status.amounts.length; ++i) {
            totalOperatorStake += status.amounts[i];
        }

        if (totalOperatorStake < parameters.MINIMUM_OPERATOR_STAKE()) {
            status.active = false;
        } else {
            status.active = true;
        }

        return status;
    }

    /// @notice Get the amount staked by an operator for a given collateral asset.
    function getOperatorStake(address operator, address collateral) public view returns (uint256) {
        EnumerableMapV2.Operator memory operatorData = operators.get(operator);

        return IBoltMiddlewareV1(operatorData.middleware).getOperatorStake(operator, collateral);
    }

    /// @notice Get the total amount staked of a given collateral asset.
    function getTotalStake(
        address collateral
    ) public view returns (uint256 amount) {
        // Loop over all of the operators, get their middleware, and retrieve their staked amount.
        for (uint256 i = 0; i < operators.length(); ++i) {
            (address operator, EnumerableMapV2.Operator memory operatorData) = operators.at(i);
            amount += IBoltMiddlewareV1(operatorData.middleware).getOperatorStake(operator, collateral);
        }

        return amount;
    }

    // ========= OPERATOR FUNCTIONS ====== //

    /// @notice Registers an operator with Bolt. Only callable by a supported middleware contract.
    function registerOperator(address operatorAddr, string calldata rpc, address curator) external onlyMiddleware {
        if (operators.contains(operatorAddr)) {
            revert OperatorAlreadyRegistered();
        }

        // check curator support interface (ERC165) and prevent invalid curator
        if (curator != address(0) && !IERC165(curator).supportsInterface(type(ICredibleCommitmentCurationProvider).interfaceId)) {
            revert InvalidCurator();
        }

        // Create an already enabled operator
        EnumerableMapV2.Operator memory operator = EnumerableMapV2.Operator(rpc, msg.sender, Time.timestamp(), curator);

        operators.set(operatorAddr, operator);
    }

    /// @notice De-registers an operator from Bolt. Only callable by a supported middleware contract.
    function deregisterOperator(
        address operator
    ) public onlyMiddleware {
        operators.remove(operator);
    }

    /// @notice Allow an operator to signal indefinite opt-out from Bolt Protocol.
    /// @dev Pausing activity does not prevent the operator from being slashable for
    /// the current network epoch until the end of the slashing window.
    function pauseOperator(
        address operator
    ) external onlyMiddleware {
        // SAFETY: This will revert if the operator key is not present.
        operators.disable(operator);
    }

    /// @notice Allow a disabled operator to signal opt-in to Bolt Protocol.
    function unpauseOperator(
        address operator
    ) external onlyMiddleware {
        // SAFETY: This will revert if the operator key is not present.
        operators.enable(operator);
    }

    /// @notice Check if an operator is currently enabled to work in Bolt Protocol.
    /// @param operator The operator address to check the enabled status for.
    /// @return True if the operator is enabled, false otherwise.
    function isOperatorEnabled(
        address operator
    ) public view returns (bool) {
        if (!operators.contains(operator)) {
            revert OperatorNotRegistered();
        }

        (uint48 enabledTime, uint48 disabledTime) = operators.getTimes(operator);
        return enabledTime != 0 && disabledTime == 0;
    }

    // ========= ADMIN FUNCTIONS ========= //

    /// @notice Add a restaking protocol into Bolt
    /// @param protocolMiddleware The address of the restaking protocol Bolt middleware
    function addRestakingProtocol(
        address protocolMiddleware
    ) public onlyOwner {
        restakingProtocols.add(protocolMiddleware);
    }

    /// @notice Remove a restaking protocol from Bolt
    /// @param protocolMiddleware The address of the restaking protocol Bolt middleware
    function removeRestakingProtocol(
        address protocolMiddleware
    ) public onlyOwner {
        restakingProtocols.remove(protocolMiddleware);
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
