// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";
import {DelegatorFactory} from "@symbiotic/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "@symbiotic/contracts/SlasherFactory.sol";
import {NetworkRegistry} from "@symbiotic/contracts/NetworkRegistry.sol";
import {OperatorRegistry} from "@symbiotic/contracts/OperatorRegistry.sol";
import {MetadataService} from "@symbiotic/contracts/service/MetadataService.sol";
import {NetworkMiddlewareService} from "@symbiotic/contracts/service/NetworkMiddlewareService.sol";
import {OptInService} from "@symbiotic/contracts/service/OptInService.sol";

import {Vault} from "@symbiotic/contracts/vault/Vault.sol";
import {NetworkRestakeDelegator} from "@symbiotic/contracts/delegator/NetworkRestakeDelegator.sol";
import {FullRestakeDelegator} from "@symbiotic/contracts/delegator/FullRestakeDelegator.sol";
import {Slasher} from "@symbiotic/contracts/slasher/Slasher.sol";
import {VetoSlasher} from "@symbiotic/contracts/slasher/VetoSlasher.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {VaultConfigurator} from "@symbiotic/contracts/VaultConfigurator.sol";

contract SymbioticSetupFixture is Test {
    function setUp(
        address deployer,
        address owner
    )
        public
        returns (
            address vaultFactory,
            address delegatorFactory,
            address slasherFactory,
            address networkRegistry,
            address operatorRegistry,
            address operatorMetadataService,
            address networkMetadataService,
            address networkMiddlewareService,
            address operatorVaultOptInService,
            address operatorNetworkOptInService,
            address slasherImpl,
            address vetoSlasherImpl,
            address vaultConfigurator,
            address networkRestakeDelegatorImpl,
            address fullRestakeDelegatorImpl
        )
    {
        vm.startPrank(deployer);

        VaultFactory vaultFactory_ = new VaultFactory(deployer);
        DelegatorFactory delegatorFactory_ = new DelegatorFactory(deployer);
        SlasherFactory slasherFactory_ = new SlasherFactory(deployer);
        NetworkRegistry networkRegistry_ = new NetworkRegistry();
        OperatorRegistry operatorRegistry_ = new OperatorRegistry();
        MetadataService operatorMetadataService_ = new MetadataService(address(operatorRegistry));
        MetadataService networkMetadataService_ = new MetadataService(address(networkRegistry));
        NetworkMiddlewareService networkMiddlewareService_ = new NetworkMiddlewareService(address(networkRegistry));
        OptInService operatorVaultOptInService_ = new OptInService(address(operatorRegistry), address(vaultFactory));
        OptInService operatorNetworkOptInService_ =
            new OptInService(address(operatorRegistry), address(networkRegistry));

        address networkRestakeDelegatorImpl_ = address(
            new NetworkRestakeDelegator(
                address(networkRegistry_),
                address(vaultFactory_),
                address(operatorVaultOptInService_),
                address(operatorNetworkOptInService_),
                address(delegatorFactory_),
                delegatorFactory_.totalTypes()
            )
        );
        delegatorFactory_.whitelist(networkRestakeDelegatorImpl_);

        address fullRestakeDelegatorImpl_ = address(
            new FullRestakeDelegator(
                address(networkRegistry_),
                address(vaultFactory_),
                address(operatorVaultOptInService_),
                address(operatorNetworkOptInService_),
                address(delegatorFactory_),
                delegatorFactory_.totalTypes()
            )
        );
        delegatorFactory_.whitelist(fullRestakeDelegatorImpl_);

        address slasherImpl_ = address(
            new Slasher(
                address(vaultFactory_),
                address(networkMiddlewareService_),
                address(slasherFactory_),
                slasherFactory_.totalTypes()
            )
        );
        slasherFactory_.whitelist(slasherImpl_);

        address vetoSlasherImpl_ = address(
            new VetoSlasher(
                address(vaultFactory_),
                address(networkMiddlewareService_),
                address(networkRegistry_),
                address(slasherFactory_),
                slasherFactory_.totalTypes()
            )
        );
        slasherFactory_.whitelist(vetoSlasherImpl_);

        VaultConfigurator vaultConfigurator_ =
            new VaultConfigurator(address(vaultFactory_), address(delegatorFactory_), address(slasherFactory_));

        vaultFactory_.transferOwnership(owner);
        delegatorFactory_.transferOwnership(owner);
        slasherFactory_.transferOwnership(owner);

        vm.stopPrank();

        return (
            address(vaultFactory_),
            address(delegatorFactory_),
            address(slasherFactory_),
            address(networkRegistry_),
            address(operatorRegistry_),
            address(operatorMetadataService_),
            address(networkMetadataService_),
            address(networkMiddlewareService_),
            address(operatorVaultOptInService_),
            address(operatorNetworkOptInService_),
            address(slasherImpl_),
            address(vetoSlasherImpl_),
            address(vaultConfigurator_),
            address(networkRestakeDelegatorImpl_),
            address(fullRestakeDelegatorImpl_)
        );
    }

    function configureVault(
        address vaultConfigurator,
        IVaultConfigurator.InitParams memory params
    ) public returns (address vault) {
        (address vault_, address networkRestakeDelegator_, address slasher_) =
            IVaultConfigurator(vaultConfigurator).create(params);

        // IVaultConfigurator.InitParams({
        //     version: 1,
        //     owner: owner_,
        //     vaultParams: IVault.InitParams({
        //         collateral: address(collateral),
        //         delegator: address(0),
        //         slasher: address(0),
        //         burner: burner,
        //         epochDuration: epochDuration,
        //         depositWhitelist: depositWhitelist,
        //         isDepositLimit: isDepositLimit,
        //         depositLimit: depositLimit,
        //         defaultAdminRoleHolder: address(100),
        //         depositWhitelistSetRoleHolder: address(99),
        //         depositorWhitelistRoleHolder: address(101),
        //         isDepositLimitSetRoleHolder: address(102),
        //         depositLimitSetRoleHolder: address(103)
        //     }),
        //     delegatorIndex: 0,
        //     delegatorParams: abi.encode(
        //         INetworkRestakeDelegator.InitParams({
        //             baseParams: IBaseDelegator.BaseParams({
        //                 defaultAdminRoleHolder: address(104),
        //                 hook: hook,
        //                 hookSetRoleHolder: address(105)
        //             }),
        //             networkLimitSetRoleHolders: networkLimitSetRoleHolders,
        //             operatorNetworkSharesSetRoleHolders: operatorNetworkSharesSetRoleHolders
        //         })
        //     ),
        //     withSlasher: withSlasher,
        //     slasherIndex: 0,
        //     slasherParams: ""
        // })

        // vault = Vault(vault_);
        // networkRestakeDelegator = NetworkRestakeDelegator(networkRestakeDelegator_);
        // slasher = Slasher(slasher_);

        // assertEq(vault.owner(), owner_);
        // assertEq(vault.collateral(), address(collateral));
        // assertEq(vault.delegator(), networkRestakeDelegator_);
        // assertEq(vault.slasher(), withSlasher ? slasher_ : address(0));
        // assertEq(vault.burner(), burner);
        // assertEq(vault.epochDuration(), epochDuration);
        // assertEq(vault.depositWhitelist(), depositWhitelist);
        // assertEq(vault.isDepositLimit(), isDepositLimit);
        // assertEq(vault.depositLimit(), depositLimit);
        // assertEq(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), address(100)), true);
        // assertEq(vault.hasRole(vault.DEPOSIT_WHITELIST_SET_ROLE(), address(99)), true);
        // assertEq(vault.hasRole(vault.DEPOSITOR_WHITELIST_ROLE(), address(101)), true);
        // assertEq(vault.hasRole(vault.IS_DEPOSIT_LIMIT_SET_ROLE(), address(102)), true);
        // assertEq(vault.hasRole(vault.DEPOSIT_LIMIT_SET_ROLE(), address(103)), true);

        // assertEq(networkRestakeDelegator.vault(), vault_);
        // assertEq(networkRestakeDelegator.hasRole(networkRestakeDelegator.DEFAULT_ADMIN_ROLE(), address(104)), true);
        // assertEq(networkRestakeDelegator.hook(), hook);
        // assertEq(networkRestakeDelegator.hasRole(networkRestakeDelegator.HOOK_SET_ROLE(), address(105)), true);
        // assertEq(networkRestakeDelegator.hasRole(networkRestakeDelegator.NETWORK_LIMIT_SET_ROLE(), address(106)), true);
        // assertEq(
        //     networkRestakeDelegator.hasRole(networkRestakeDelegator.OPERATOR_NETWORK_SHARES_SET_ROLE(), address(107)),
        //     true
        // );

        // if (withSlasher) {
        //     assertEq(slasher.vault(), vault_);
        // }

        assertEq(networkRestakeDelegator_, address(Vault(vault_).delegator()));
        assertEq(slasher_, address(Vault(vault_).slasher()));

        return vault_;
    }
}
