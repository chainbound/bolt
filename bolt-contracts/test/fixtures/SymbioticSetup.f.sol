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
            address vaultConfigurator
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
            address(vaultConfigurator_)
        );
    }
}
