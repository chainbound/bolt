// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";

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

import {VaultConfigurator} from "@symbiotic/contracts/VaultConfigurator.sol";

contract SymbioticSetupFixture is Script {
    function setup(
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
            address vaultImpl,
            address networkRestakeDelegatorImpl,
            address fullRestakeDelegatorImpl
        )
    {
        vm.startPrank(deployer);

        VaultFactory vaultFactory = new VaultFactory(deployer);
        DelegatorFactory delegatorFactory = new DelegatorFactory(deployer);
        SlasherFactory slasherFactory = new SlasherFactory(deployer);
        NetworkRegistry networkRegistry = new NetworkRegistry();
        OperatorRegistry operatorRegistry = new OperatorRegistry();
        MetadataService operatorMetadataService = new MetadataService(address(operatorRegistry));
        MetadataService networkMetadataService = new MetadataService(address(networkRegistry));
        NetworkMiddlewareService networkMiddlewareService = new NetworkMiddlewareService(address(networkRegistry));
        OptInService operatorVaultOptInService = new OptInService(address(operatorRegistry), address(vaultFactory));
        OptInService operatorNetworkOptInService = new OptInService(address(operatorRegistry), address(networkRegistry));

        address vaultImpl =
            address(new Vault(address(delegatorFactory), address(slasherFactory), address(vaultFactory)));
        vaultFactory.whitelist(vaultImpl);

        address networkRestakeDelegatorImpl = address(
            new NetworkRestakeDelegator(
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(networkRestakeDelegatorImpl);

        address fullRestakeDelegatorImpl = address(
            new FullRestakeDelegator(
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(fullRestakeDelegatorImpl);

        address slasherImpl = address(
            new Slasher(
                address(vaultFactory),
                address(networkMiddlewareService),
                address(slasherFactory),
                slasherFactory.totalTypes()
            )
        );
        slasherFactory.whitelist(slasherImpl);

        address vetoSlasherImpl = address(
            new VetoSlasher(
                address(vaultFactory),
                address(networkMiddlewareService),
                address(networkRegistry),
                address(slasherFactory),
                slasherFactory.totalTypes()
            )
        );
        slasherFactory.whitelist(vetoSlasherImpl);

        VaultConfigurator vaultConfigurator =
            new VaultConfigurator(address(vaultFactory), address(delegatorFactory), address(slasherFactory));

        vaultFactory.transferOwnership(owner);
        delegatorFactory.transferOwnership(owner);
        slasherFactory.transferOwnership(owner);

        vm.stopPrank();

        return (
            address(vaultFactory),
            address(delegatorFactory),
            address(slasherFactory),
            address(networkRegistry),
            address(operatorRegistry),
            address(operatorMetadataService),
            address(networkMetadataService),
            address(networkMiddlewareService),
            address(operatorVaultOptInService),
            address(operatorNetworkOptInService),
            address(slasherImpl),
            address(vetoSlasherImpl),
            address(vaultConfigurator),
            address(vaultImpl),
            address(networkRestakeDelegatorImpl),
            address(fullRestakeDelegatorImpl)
        );
    }
}
