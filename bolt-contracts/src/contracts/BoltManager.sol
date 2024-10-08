// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {Time} from "lib/openzeppelin-contracts/contracts/utils/types/Time.sol";
import {EnumerableSet} from "lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IRegistry} from "@symbiotic/interfaces/common/IRegistry.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {IEntity} from "@symbiotic/interfaces/common/IEntity.sol";

import {OperatorMapWithTime} from "../lib/OperatorMapWithTime.sol";
import {EnumerableMap} from "../lib/EnumerableMap.sol";
import {IBoltValidators} from "../interfaces/IBoltValidators.sol";
import {IBoltMiddleware} from "../interfaces/IBoltMiddleware.sol";
import {IBoltManager} from "../interfaces/IBoltManager.sol";

contract BoltManager is IBoltManager, Ownable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.OperatorMap;
    using OperatorMapWithTime for EnumerableMap.OperatorMap;
    using Subnetwork for address;

    // ========= STORAGE =========

    /// @notice Validators registry, where validators are registered via their
    /// BLS pubkey and are assigned a sequence number.
    IBoltValidators public validators;

    /// @notice Set of operator addresses that have opted in to Bolt Protocol.
    EnumerableMap.OperatorMap private operators;

    /// @notice Mapping of operator addresses to RPC endpoints.
    mapping(address => string) private operatorRPCs;

    /// @notice Set of restaking protocols supported. Each address corresponds to the
    /// associated Bolt Middleware contract.
    EnumerableSet.AddressSet private restakingProtocols;

    // ============= IMMUTABLES ================ //
    /// @notice Start timestamp of the first epoch.
    uint48 public immutable START_TIMESTAMP;

    // ============= CONSTANTS ================= //
    /// @notice Duration of an epoch in seconds.
    uint48 public constant EPOCH_DURATION = 1 days;

    modifier onlyMiddleware() {
        require(restakingProtocols.contains(msg.sender), "BoltManager: caller is not a middleware");
        _;
    }

    // ========= CONSTRUCTOR =========

    /// @notice Constructor for the BoltManager contract.
    /// @param _validators The address of the validators registry.
    constructor(address _owner, address _validators) Ownable(_owner) {
        validators = IBoltValidators(_validators);
        START_TIMESTAMP = Time.timestamp();
    }

    // ========= VIEW FUNCTIONS =========

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

    // ========= OPERATOR FUNCTIONS ====== //

    /// @notice Registers an operator with Bolt. Only callable by a supported middleware contract.
    function registerOperator(address operator, string calldata rpc) external onlyMiddleware {
        if (operators.contains(operator)) {
            revert OperatorAlreadyRegistered();
        }

        operators.add(operator);
        operators.enable(operator);

        operatorRPCs[operator] = rpc;
    }

    /// @notice De-registers an operator from Bolt. Only callable by a supported middleware contract.
    function deregisterOperator(
        address operator
    ) public onlyMiddleware {
        operators.remove(operator);

        delete operatorRPCs[operator];
    }

    /// @notice Allow an operator to signal indefinite opt-out from Bolt Protocol.
    /// @dev Pausing activity does not prevent the operator from being slashable for
    /// the current network epoch until the end of the slashing window.
    function pauseOperator(
        address operator
    ) external onlyMiddleware {
        operators.disable(operator);
    }

    /// @notice Allow a disabled operator to signal opt-in to Bolt Protocol.
    function unpauseOperator(
        address operator
    ) external onlyMiddleware {
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

    /// @notice Get the status of multiple proposers, given their pubkey hashes.
    /// @param pubkeyHashes The pubkey hashes of the proposers to get the status for.
    /// @return statuses The statuses of the proposers, including their operator and active stake.
    function getProposersStatus(
        bytes32[] calldata pubkeyHashes
    ) public view returns (IBoltValidators.ProposerStatus[] memory statuses) {
        statuses = new IBoltValidators.ProposerStatus[](pubkeyHashes.length);
        for (uint256 i = 0; i < pubkeyHashes.length; ++i) {
            statuses[i] = getProposerStatus(pubkeyHashes[i]);
        }
    }

    /// @notice Get the status of a proposer, given their pubkey hash.
    /// @param pubkeyHash The pubkey hash of the proposer to get the status for.
    /// @return status The status of the proposer, including their operator and active stake.
    function getProposerStatus(
        bytes32 pubkeyHash
    ) public view returns (IBoltValidators.ProposerStatus memory status) {
        if (pubkeyHash == bytes32(0)) {
            revert InvalidQuery();
        }

        uint48 epochStartTs = getEpochStartTs(getEpochAtTs(Time.timestamp()));
        IBoltValidators.Validator memory validator = validators.getValidatorByPubkeyHash(pubkeyHash);

        Operator memory operator = operators.get(validator.authorizedOperator);

        status.pubkeyHash = pubkeyHash;
        status.active = validator.exists;
        status.operator = validator.authorizedOperator;
        status.operatorRPC = operator.rpc;

        (uint48 enabledTime, uint48 disabledTime) = operators.getTimes(validator.authorizedOperator);
        if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
            return status;
        }

        (status.collaterals, status.amounts) =
            IBoltMiddleware(operator.middleware).getOperatorCollaterals(validator.authorizedOperator);

        return status;
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
