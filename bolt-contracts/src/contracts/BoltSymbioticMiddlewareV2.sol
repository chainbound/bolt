// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IRegistry} from "@symbiotic/interfaces/common/IRegistry.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {IEntity} from "@symbiotic/interfaces/common/IEntity.sol";

import {MapWithTimeData} from "../lib/MapWithTimeData.sol";
import {IBoltParametersV1} from "../interfaces/IBoltParametersV1.sol";
import {IBoltMiddlewareV1} from "../interfaces/IBoltMiddlewareV1.sol";
import {IBoltManagerV1} from "../interfaces/IBoltManagerV1.sol";

/// @title Bolt Symbiotic Middleware
/// @notice This contract is responsible for interfacing with the Symbiotic restaking protocol.
/// @dev This contract is upgradeable using the UUPSProxy pattern. Storage layout remains fixed across upgrades
/// with the use of storage gaps.
/// See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
/// To validate the storage layout, use the Openzeppelin Foundry Upgrades toolkit.
/// You can also validate manually with forge: forge inspect <contract> storage-layout --pretty
contract BoltSymbioticMiddlewareV2 is IBoltMiddlewareV1, OwnableUpgradeable, EIP712, UUPSUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;
    using Subnetwork for address;

    // ========== CONSTANTS ============ //
    /// @notice Slasher that can instantly slash operators without veto.
    uint256 public INSTANT_SLASHER_TYPE = 0;

    /// @notice Slasher that can request a veto before actually slashing operators.
    uint256 public VETO_SLASHER_TYPE = 1;

    // ========= STORAGE ========= //

    /// @notice Start timestamp of the first epoch.
    uint48 public START_TIMESTAMP;

    /// @notice Bolt Parameters contract.
    IBoltParametersV1 public parameters;

    /// @notice Validators registry, where validators are registered via their
    /// BLS pubkey and are assigned a sequence number.
    IBoltManagerV1 public manager;

    /// @notice Set of Symbiotic protocol vaults that are used in Bolt Protocol.
    EnumerableMap.AddressToUintMap private vaults;

    /// @notice Address of the Bolt network in Symbiotic Protocol.
    address public BOLT_SYMBIOTIC_NETWORK;

    /// @notice Address of the Symbiotic Operator Registry contract.
    address public OPERATOR_REGISTRY;

    /// @notice Address of the Symbiotic Vault Factory contract.
    address public VAULT_FACTORY;

    /// @notice Address of the Symbiotic Operator Network Opt-In contract.
    address public OPERATOR_NET_OPTIN;

    bytes32 public NAME_HASH;

    // --> Storage layout marker: 12 slots

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     * This can be validated with the Openzeppelin Foundry Upgrades toolkit.
     *
     * Total storage slots: 50
     */
    uint256[38] private __gap;

    // ========= ERRORS =========

    error NotVault();
    error SlashAmountTooHigh();
    error UnknownSlasherType();

    // ========= CONSTRUCTOR =========

    /// @notice Constructor for the BoltSymbioticMiddleware contract.
    /// @param _parameters The address of the Bolt Parameters contract.
    /// @param _manager The address of the Bolt Manager contract.
    /// @param _symbioticNetwork The address of the Symbiotic network.
    /// @param _symbioticOperatorRegistry The address of the Symbiotic operator registry.
    /// @param _symbioticOperatorNetOptIn The address of the Symbiotic operator network opt-in contract.
    /// @param _symbioticVaultFactory The address of the Symbiotic vault registry.
    function initialize(
        address _owner,
        address _parameters,
        address _manager,
        address _symbioticNetwork,
        address _symbioticOperatorRegistry,
        address _symbioticOperatorNetOptIn,
        address _symbioticVaultFactory
    ) public initializer {
        __Ownable_init(_owner);
        parameters = IBoltParametersV1(_parameters);
        manager = IBoltManagerV1(_manager);
        START_TIMESTAMP = Time.timestamp();

        BOLT_SYMBIOTIC_NETWORK = _symbioticNetwork;
        OPERATOR_REGISTRY = _symbioticOperatorRegistry;
        OPERATOR_NET_OPTIN = _symbioticOperatorNetOptIn;
        VAULT_FACTORY = _symbioticVaultFactory;
        NAME_HASH = keccak256("SYMBIOTIC");
    }

    function initializeV2(
        address _owner,
        address _parameters,
        address _manager,
        address _symbioticNetwork,
        address _symbioticOperatorRegistry,
        address _symbioticOperatorNetOptIn,
        address _symbioticVaultFactory
    ) public reinitializer(2) {
        __Ownable_init(_owner);
        parameters = IBoltParametersV1(_parameters);
        manager = IBoltManagerV1(_manager);
        START_TIMESTAMP = Time.timestamp();

        BOLT_SYMBIOTIC_NETWORK = _symbioticNetwork;
        OPERATOR_REGISTRY = _symbioticOperatorRegistry;
        OPERATOR_NET_OPTIN = _symbioticOperatorNetOptIn;
        VAULT_FACTORY = _symbioticVaultFactory;
        NAME_HASH = keccak256("SYMBIOTIC");
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // ========= VIEW FUNCTIONS =========

    /// @notice Get the start timestamp of an epoch.
    function getEpochStartTs(uint48 epoch) public view returns (uint48 timestamp) {
        return START_TIMESTAMP + epoch * parameters.EPOCH_DURATION();
    }

    /// @notice Get the epoch at a given timestamp.
    function getEpochAtTs(uint48 timestamp) public view returns (uint48 epoch) {
        return (timestamp - START_TIMESTAMP) / parameters.EPOCH_DURATION();
    }

    /// @notice Get the current epoch.
    function getCurrentEpoch() public view returns (uint48 epoch) {
        return getEpochAtTs(Time.timestamp());
    }

    /// @notice Get the whitelisted vaults.
    function getWhitelistedVaults() public view returns (address[] memory) {
        return vaults.keys();
    }

    // =========== ADMIN FUNCTIONS ============ //

    /// @notice Allow a vault to signal opt-in to Bolt Protocol.
    /// @param vault The vault address to signal opt-in for.
    function registerVault(address vault) public onlyOwner {
        if (vaults.contains(vault)) {
            revert AlreadyRegistered();
        }

        if (!IRegistry(VAULT_FACTORY).isEntity(vault)) {
            revert NotVault();
        }

        // TODO: check slashing conditions and veto duration

        vaults.add(vault);
        vaults.enable(vault);
    }

    /// @notice Deregister a vault from working in Bolt Protocol.
    /// @param vault The vault address to deregister.
    function deregisterVault(address vault) public onlyOwner {
        if (!vaults.contains(vault)) {
            revert NotRegistered();
        }

        vaults.remove(vault);
    }

    // ========= SYMBIOTIC MIDDLEWARE LOGIC =========

    function registerOperator(
        address operator,
        string calldata rpc,
        address curator,
        uint48 deadline,
        bytes calldata signature
    ) public {
        if (deadline < Time.timestamp()) {
            revert ExpiredSignature();
        }

        if (
            !SignatureChecker.isValidSignatureNow(
                operator,
                _hashTypedDataV4(keccak256(abi.encode(msg.sender, operator, rpc, curator, deadline))),
                signature
            )
        ) {
            revert InvalidSignature();
        }

        _registerOperator(operator, rpc, curator);
    }

    /// @notice Allow an operator to signal opt-in to Bolt Protocol.
    /// msg.sender must be an operator in the Symbiotic network.
    function registerOperator(string calldata rpc, address curator) public {
        _registerOperator(msg.sender, rpc, curator);
    }

    function _registerOperator(address operator, string calldata rpc, address curator) internal {
        if (manager.isOperator(operator)) {
            revert AlreadyRegistered();
        }

        if (!IRegistry(OPERATOR_REGISTRY).isEntity(operator)) {
            revert NotOperator();
        }

        if (!IOptInService(OPERATOR_NET_OPTIN).isOptedIn(operator, BOLT_SYMBIOTIC_NETWORK)) {
            revert OperatorNotOptedIn();
        }

        manager.registerOperator(operator, rpc, curator);
    }

    /// @notice Deregister a Symbiotic operator from working in Bolt Protocol.
    /// @dev This does NOT deregister the operator from the Symbiotic network.
    function deregisterOperator() public {
        if (!manager.isOperator(msg.sender)) {
            revert NotRegistered();
        }

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
    function isVaultEnabled(address vault) public view returns (bool) {
        (uint48 enabledTime, uint48 disabledTime) = vaults.getTimes(vault);
        return enabledTime != 0 && disabledTime == 0;
    }

    /// @notice Get the collaterals and amounts staked by an operator across the supported strategies.
    ///
    /// @param operator The operator address to get the collaterals and amounts staked for.
    /// @return collaterals The collaterals staked by the operator.
    /// @dev Assumes that the operator is registered and enabled.
    function getOperatorCollaterals(address operator) public view returns (address[] memory, uint256[] memory) {
        address[] memory collateralTokens = new address[](vaults.length());
        uint256[] memory amounts = new uint256[](vaults.length());

        uint48 epochStartTs = getEpochStartTs(getEpochAtTs(Time.timestamp()));

        for (uint256 i = 0; i < vaults.length(); ++i) {
            (address vault, uint48 enabledTime, uint48 disabledTime) = vaults.atWithTimes(i);

            if (!_wasEnabledAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            address collateral = IVault(vault).collateral();
            collateralTokens[i] = collateral;

            // in order to have stake in a network, the operator needs to be opted in to that vault.
            // this authorization is fully handled in the Vault, we just need to read the stake.
            amounts[i] = IBaseDelegator(IVault(vault).delegator()).stakeAt(
                // The stake for each subnetwork is stored in the vault's delegator contract.
                // stakeAt returns the stake of "operator" at "timestamp" for "network" (or subnetwork)
                // bytes(0) is for hints, which we don't currently use.
                BOLT_SYMBIOTIC_NETWORK.subnetwork(0),
                operator,
                epochStartTs,
                new bytes(0)
            );
        }

        return (collateralTokens, amounts);
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
