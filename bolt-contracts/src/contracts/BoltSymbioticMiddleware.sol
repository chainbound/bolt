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
import {IBoltMiddleware} from "../interfaces/IBoltMiddleware.sol";
import {IBoltManager} from "../interfaces/IBoltManager.sol";

contract BoltSymbioticMiddleware is IBoltMiddleware, Ownable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;
    using Subnetwork for address;

    // ========= STORAGE =========

    /// @notice Validators registry, where validators are registered via their
    /// BLS pubkey and are assigned a sequence number.
    IBoltManager public boltManager;

    /// @notice Set of Symbiotic operator addresses that have opted in to Bolt Protocol.
    EnumerableMap.AddressToUintMap private operators;

    /// @notice Mapping of operator addresses to RPC endpoints.
    mapping(address => string) private operatorRPCs;

    /// @notice Set of Symbiotic protocol vaults that are used in Bolt Protocol.
    EnumerableMap.AddressToUintMap private vaults;

    /// @notice Set of Symbiotic collateral addresses that are whitelisted.
    EnumerableSet.AddressSet private whitelistedCollaterals;

    // ========= IMMUTABLES =========

    /// @notice Address of the Bolt network in Symbiotic Protocol.
    address public immutable BOLT_SYMBIOTIC_NETWORK;

    /// @notice Address of the Symbiotic Operator Registry contract.
    address public immutable OPERATOR_REGISTRY;

    /// @notice Address of the Symbiotic Vault Registry contract.
    address public immutable VAULT_REGISTRY;

    /// @notice Address of the Symbiotic Operator Network Opt-In contract.
    address public immutable OPERATOR_NET_OPTIN;

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

    bytes32 public constant NAME_HASH = keccak256("SYMBIOTIC");

    // ========= ERRORS =========

    error NotVault();
    error SlashAmountTooHigh();
    error UnknownSlasherType();

    // ========= CONSTRUCTOR =========

    /// @notice Constructor for the BoltSymbioticMiddleware contract.
    /// @param _boltManager The address of the Bolt Manager contract.
    /// @param _symbioticNetwork The address of the Symbiotic network.
    /// @param _symbioticOperatorRegistry The address of the Symbiotic operator registry.
    /// @param _symbioticOperatorNetOptIn The address of the Symbiotic operator network opt-in contract.
    /// @param _symbioticVaultRegistry The address of the Symbiotic vault registry.
    constructor(
        address _owner,
        address _boltManager,
        address _symbioticNetwork,
        address _symbioticOperatorRegistry,
        address _symbioticOperatorNetOptIn,
        address _symbioticVaultRegistry
    ) Ownable(_owner) {
        boltManager = IBoltManager(_boltManager);
        START_TIMESTAMP = Time.timestamp();

        BOLT_SYMBIOTIC_NETWORK = _symbioticNetwork;
        OPERATOR_REGISTRY = _symbioticOperatorRegistry;
        OPERATOR_NET_OPTIN = _symbioticOperatorNetOptIn;
        VAULT_REGISTRY = _symbioticVaultRegistry;
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

        return boltManager.validators().getValidatorByPubkeyHash(pubkeyHash).authorizedOperator == operator;
    }

    /// @notice Get the list of collateral addresses that are whitelisted.
    /// @return collaterals The list of collateral addresses that are whitelisted.
    function getWhitelistedCollaterals() public view returns (address[] memory collaterals) {
        return whitelistedCollaterals.values();
    }

    /// @notice Check if a collateral address is whitelisted.
    /// @param collateral The collateral address to check the whitelist status for.
    /// @return True if the collateral address is whitelisted, false otherwise.
    function isCollateralWhitelisted(
        address collateral
    ) public view returns (bool) {
        return whitelistedCollaterals.contains(collateral);
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

    // ========= SYMBIOTIC MIDDLEWARE LOGIC =========

    /// @notice Allow an operator to signal opt-in to Bolt Protocol.
    /// @param operator The operator address to signal opt-in for.
    function registerOperator(address operator, string calldata rpc) public {
        if (operators.contains(operator)) {
            revert AlreadyRegistered();
        }

        if (!IRegistry(OPERATOR_REGISTRY).isEntity(operator)) {
            revert NotOperator();
        }

        if (!IOptInService(OPERATOR_NET_OPTIN).isOptedIn(operator, BOLT_SYMBIOTIC_NETWORK)) {
            revert OperatorNotOptedIn();
        }

        operators.add(operator);
        operators.enable(operator);

        operatorRPCs[operator] = rpc;
    }

    /// @notice Deregister a Symbiotic operator from working in Bolt Protocol.
    /// @dev This does NOT deregister the operator from the Symbiotic network.
    function deregisterOperator() public {
        if (!operators.contains(msg.sender)) {
            revert NotRegistered();
        }

        operators.remove(msg.sender);

        delete operatorRPCs[msg.sender];
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

    /// @notice Allow a vault to signal opt-in to Bolt Protocol.
    /// @param vault The vault address to signal opt-in for.
    function registerVault(
        address vault
    ) public {
        if (vaults.contains(vault)) {
            revert AlreadyRegistered();
        }

        if (!IRegistry(VAULT_REGISTRY).isEntity(vault)) {
            revert NotVault();
        }

        if (!isCollateralWhitelisted(IVault(vault).collateral())) {
            revert CollateralNotWhitelisted();
        }

        // TODO: check slashing conditions and veto duration

        vaults.add(vault);
        vaults.enable(vault);
    }

    /// @notice Allow a vault to signal indefinite opt-out from Bolt Protocol.
    function pauseVault() public {
        if (!vaults.contains(msg.sender)) {
            revert NotRegistered();
        }

        vaults.disable(msg.sender);
    }

    /// @notice Allow a disabled vault to signal opt-in to Bolt Protocol.
    function unpauseVault() public {
        if (!vaults.contains(msg.sender)) {
            revert NotRegistered();
        }

        vaults.enable(msg.sender);
    }

    /// @notice Check if a vault is currently enabled to work in Bolt Protocol.
    /// @param vault The vault address to check the enabled status for.
    /// @return True if the vault is enabled, false otherwise.
    function isVaultEnabled(
        address vault
    ) public view returns (bool) {
        (uint48 enabledTime, uint48 disabledTime) = vaults.getTimes(vault);
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
        IBoltValidators.Validator memory validator = boltManager.validators().getValidatorByPubkeyHash(pubkeyHash);
        address operator = validator.authorizedOperator;

        status.pubkeyHash = pubkeyHash;
        status.active = validator.exists;
        status.operator = operator;

        (uint48 enabledTime, uint48 disabledTime) = operators.getTimes(operator);
        if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
            return status;
        }

        status.collaterals = new address[](vaults.length());
        status.amounts = new uint256[](vaults.length());

        for (uint256 i = 0; i < vaults.length(); ++i) {
            (address vault, uint48 enabledVaultTime, uint48 disabledVaultTime) = vaults.atWithTimes(i);

            address collateral = IVault(vault).collateral();
            status.collaterals[i] = collateral;
            if (!_wasEnabledAt(enabledVaultTime, disabledVaultTime, epochStartTs)) {
                continue;
            }

            status.amounts[i] = getOperatorStakeAt(operator, collateral, epochStartTs);
        }
    }

    /// @notice Get the stake of an operator in Symbiotic protocol at the current timestamp.
    /// @param operator The operator address to check the stake for.
    /// @param collateral The collateral address to check the stake for.
    /// @return amount The stake of the operator at the current timestamp, in collateral token.
    function getOperatorStake(address operator, address collateral) public view returns (uint256 amount) {
        uint48 timestamp = Time.timestamp();
        return getOperatorStakeAt(operator, collateral, timestamp);
    }

    /// @notice Get the stake of an operator in Symbiotic protocol at a given timestamp.
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

        for (uint256 i = 0; i < vaults.length(); ++i) {
            (address vault, uint48 enabledTime, uint48 disabledTime) = vaults.atWithTimes(i);

            if (collateral != IVault(vault).collateral()) {
                continue;
            }

            if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            // in order to have stake in a network, the operator needs to be opted in to that vault.
            // this authorization is fully handled in the Vault, we just need to read the stake.
            amount += IBaseDelegator(IVault(vault).delegator()).stakeAt(
                // The stake for each subnetwork is stored in the vault's delegator contract.
                // stakeAt returns the stake of "operator" at "timestamp" for "network" (or subnetwork)
                // bytes(0) is for hints, which we don't currently use.
                BOLT_SYMBIOTIC_NETWORK.subnetwork(0),
                operator,
                epochStartTs,
                new bytes(0)
            );
        }

        return amount;
    }

    /// @notice Get the total stake of all Symbiotic operators at a given epoch for a collateral asset.
    /// @param epoch The epoch to check the total stake for.
    /// @param collateral The collateral address to check the total stake for.
    /// @return totalStake The total stake of all operators at the given epoch, in collateral token.
    function getTotalStake(uint48 epoch, address collateral) public view returns (uint256 totalStake) {
        uint48 epochStartTs = getEpochStartTs(epoch);

        // for epoch older than SLASHING_WINDOW total stake can be invalidated
        if (
            epochStartTs < SLASHING_WINDOW || epochStartTs < Time.timestamp() - SLASHING_WINDOW
                || epochStartTs > Time.timestamp()
        ) {
            revert InvalidQuery();
        }

        for (uint256 i; i < operators.length(); ++i) {
            (address operator, uint48 enabledTime, uint48 disabledTime) = operators.atWithTimes(i);

            // just skip operator if it was added after the target epoch or paused
            if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            totalStake += getOperatorStakeAt(operator, collateral, epochStartTs);
        }
    }

    /// @notice Slash a given operator for a given amount of collateral.
    /// @param timestamp The timestamp of the slash event.
    /// @param operator The operator address to slash.
    /// @param collateral The collateral address to slash.
    /// @param amount The amount of collateral to slash.
    function slash(uint48 timestamp, address operator, address collateral, uint256 amount) public onlyOwner {
        // TODO: remove onlyOwner modifier and gate the slashing logic behind the BoltChallenger
        // fault proof mechanism to allow for permissionless slashing.

        uint48 epochStartTs = getEpochStartTs(getEpochAtTs(timestamp));

        for (uint256 i = 0; i < vaults.length(); ++i) {
            (address vault, uint48 enabledTime, uint48 disabledTime) = vaults.atWithTimes(i);

            if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            if (collateral != IVault(vault).collateral()) {
                continue;
            }

            uint256 operatorStake = getOperatorStakeAt(operator, collateral, epochStartTs);

            if (amount > operatorStake) {
                revert SlashAmountTooHigh();
            }

            uint256 vaultStake = IBaseDelegator(IVault(vault).delegator()).stakeAt(
                BOLT_SYMBIOTIC_NETWORK.subnetwork(0), operator, epochStartTs, new bytes(0)
            );

            // Slash the vault pro-rata.
            _slashVault(epochStartTs, vault, operator, (amount * vaultStake) / operatorStake);
        }
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

    /// @notice Slash an operator for a given amount of collateral.
    /// @param timestamp The timestamp of the slash event.
    /// @param operator The operator address to slash.
    /// @param amount The amount of collateral to slash.
    function _slashVault(uint48 timestamp, address vault, address operator, uint256 amount) private {
        address slasher = IVault(vault).slasher();
        uint256 slasherType = IEntity(slasher).TYPE();

        if (slasherType == INSTANT_SLASHER_TYPE) {
            ISlasher(slasher).slash(BOLT_SYMBIOTIC_NETWORK.subnetwork(0), operator, amount, timestamp, new bytes(0));
        } else if (slasherType == VETO_SLASHER_TYPE) {
            IVetoSlasher(slasher).requestSlash(
                BOLT_SYMBIOTIC_NETWORK.subnetwork(0), operator, amount, timestamp, new bytes(0)
            );
        } else {
            revert UnknownSlasherType();
        }
    }
}
