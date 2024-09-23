// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {Time} from "lib/openzeppelin-contracts/contracts/utils/types/Time.sol";
import {EnumerableMap} from "lib/openzeppelin-contracts/contracts/utils/structs/EnumerableMap.sol";
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

import {MapWithTimeData} from "../lib/MapWithTimeData.sol";
import {IBoltValidators} from "../interfaces/IBoltValidators.sol";
import {IBoltManager} from "../interfaces/IBoltManager.sol";
import {IBoltMiddleware} from "../interfaces/IBoltMiddleware.sol";

contract BoltManager is IBoltManager, Ownable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;
    using Subnetwork for address;

    // ========= STORAGE =========

    /// @notice Validators registry, where validators are registered via their
    /// BLS pubkey and are assigned a sequence number.
    IBoltValidators public validators;

    /// @notice Set of restaking protocols supported. Each address corresponds to the
    /// associated Bolt Middleware contract.
    EnumerableSet.AddressSet private restakingProtocols;

    // ========= IMMUTABLES =========

    /// @notice Start timestamp of the first epoch.
    uint48 public immutable START_TIMESTAMP;

    // ========= CONSTANTS =========

    /// @notice Duration of an epoch in seconds.
    uint48 public constant EPOCH_DURATION = 1 days;

    /// @notice Duration of the slashing window in seconds.
    uint48 public constant SLASHING_WINDOW = 7 days;

    // ========= CONSTRUCTOR =========

    /// @notice Constructor for the BoltManager contract.
    /// @param _validators The address of the validators registry.
    constructor(address _owner, address _validators) Ownable(_owner) {
        validators = IBoltValidators(_validators);
        START_TIMESTAMP = Time.timestamp();
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

    // ========= ADMIN FUNCTIONS =========

    /// @notice Add a restaking protocol into Bolt
    /// @param protocolMiddleware The address of the restaking protocol Bolt middleware
    function addRestakingProtocol(
        IBoltMiddleware protocolMiddleware
    ) public onlyOwner {
        restakingProtocols.add(address(protocolMiddleware));
    }

    /// @notice Remove a restaking protocol from Bolt
    /// @param protocolMiddleware The address of the restaking protocol Bolt middleware
    function removeRestakingProtocol(
        IBoltMiddleware protocolMiddleware
    ) public onlyOwner {
        restakingProtocols.remove(address(protocolMiddleware));
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
