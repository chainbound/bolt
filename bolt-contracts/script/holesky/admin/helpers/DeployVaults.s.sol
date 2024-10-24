// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {IBaseSlasher} from "@symbiotic/interfaces/slasher/IBaseSlasher.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {IMigratablesFactory} from "@symbiotic/interfaces/common/IMigratablesFactory.sol";

contract DeploySymbioticVaults is Script {
    struct VaultConfig {
        address admin;
        address collateral;
    }

    function run() public {
        IVaultConfigurator vaultConfigurator = _readVaultConfigurator();
        VaultConfig[] memory configs = _readVaultConfigs();
        uint48 epochDuration = _readEpochDuration();

        // TODO: Check if vaults for specific collateral are already deployed!

        vm.startBroadcast();

        for (uint256 i; i < configs.length; ++i) {
            VaultConfig memory config = configs[i];

            IMigratablesFactory vaultFactory = IMigratablesFactory(vaultConfigurator.VAULT_FACTORY());

            bool exists;

            // First check if the vault already exists. We do this by checking for the collateral, and the admin.
            // If we need to check for more properties in the future (like version), we can add them here.
            for (uint256 j; j < vaultFactory.totalEntities(); ++j) {
                address existingVault = vaultFactory.entity(j);

                if (
                    IVault(existingVault).collateral() == config.collateral
                        && OwnableUpgradeable(existingVault).owner() == config.admin
                ) {
                    console.log(
                        "Vault for collateral %s already deployed with admin %s", config.collateral, config.admin
                    );
                    console.log("Address:", existingVault);
                    exists = true;

                    break;
                }
            }

            if (exists) {
                continue;
            }

            address[] memory adminRoleHolders = new address[](1);
            adminRoleHolders[0] = config.admin;

            IVaultConfigurator.InitParams memory vaultConfiguratorInitParams = IVaultConfigurator.InitParams({
                // Use Version 1 for a standard vault (non-tokenized).
                version: 1,
                owner: config.admin,
                vaultParams: abi.encode(
                    IVault.InitParams({
                        collateral: config.collateral,
                        burner: address(0xdead),
                        epochDuration: epochDuration,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: config.admin,
                        depositWhitelistSetRoleHolder: config.admin,
                        depositorWhitelistRoleHolder: config.admin,
                        isDepositLimitSetRoleHolder: config.admin,
                        depositLimitSetRoleHolder: config.admin
                    })
                ),
                delegatorIndex: 0, // Use NetworkRestakeDelegator
                delegatorParams: abi.encode(
                    INetworkRestakeDelegator.InitParams({
                        baseParams: IBaseDelegator.BaseParams({
                            defaultAdminRoleHolder: config.admin,
                            hook: address(0), // we don't need a hook
                            hookSetRoleHolder: config.admin
                        }),
                        networkLimitSetRoleHolders: adminRoleHolders,
                        operatorNetworkSharesSetRoleHolders: adminRoleHolders
                    })
                ),
                withSlasher: true,
                slasherIndex: 1, // Use VetoSlasher
                slasherParams: abi.encode(
                    IVetoSlasher.InitParams({
                        baseParams: IBaseSlasher.BaseParams({
                            isBurnerHook: false // ?
                        }),
                        // veto duration must be smaller than epoch duration
                        vetoDuration: uint48(12 hours),
                        resolverSetEpochsDelay: 3
                    })
                )
            });

            (address vault, address networkRestakeDelegator, address vetoSlasher) =
                vaultConfigurator.create(vaultConfiguratorInitParams);

            console.log("Deployed vault with collateral:", config.collateral);
            console.log("Vault address:", vault);
            console.log("NetworkRestakeDelegator:", networkRestakeDelegator);
            console.log("VetoSlasher:", vetoSlasher);
        }

        vm.stopBroadcast();
    }

    function _readVaultConfigs() internal view returns (VaultConfig[] memory configs) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/vaults.json");
        string memory json = vm.readFile(path);

        configs = abi.decode(vm.parseJson(json), (VaultConfig[]));
    }

    function _readEpochDuration() internal view returns (uint48) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/parameters.json");
        string memory json = vm.readFile(path);

        return uint48(vm.parseJsonUint(json, ".epochDuration"));
    }

    function _readVaultConfigurator() internal view returns (IVaultConfigurator) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return IVaultConfigurator(vm.parseJsonAddress(json, ".symbiotic.vaultConfigurator"));
    }
}
