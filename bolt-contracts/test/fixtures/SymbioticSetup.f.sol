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

import {SimpleCollateral} from "../mocks/SimpleCollateral.sol";
import {Token} from "../mocks/Token.sol";

contract SymbioticSetupFixture is Test {
    function setUp(
        address deployer,
        address owner
    )
        public
        returns (
            VaultFactory vaultFactory,
            DelegatorFactory delegatorFactory,
            SlasherFactory slasherFactory,
            NetworkRegistry networkRegistry,
            OperatorRegistry operatorRegistry,
            MetadataService operatorMetadataService,
            MetadataService networkMetadataService,
            NetworkMiddlewareService networkMiddlewareService,
            OptInService operatorVaultOptInService,
            OptInService operatorNetworkOptInService,
            VaultConfigurator vaultConfigurator,
            SimpleCollateral collateral
        )
    {
        vm.startPrank(deployer);

        VaultFactory vaultFactory_ = new VaultFactory(deployer);
        DelegatorFactory delegatorFactory_ = new DelegatorFactory(deployer);
        SlasherFactory slasherFactory_ = new SlasherFactory(deployer);
        NetworkRegistry networkRegistry_ = new NetworkRegistry();
        OperatorRegistry operatorRegistry_ = new OperatorRegistry();
        MetadataService operatorMetadataService_ = new MetadataService(address(operatorRegistry_));
        MetadataService networkMetadataService_ = new MetadataService(address(networkRegistry_));
        NetworkMiddlewareService networkMiddlewareService_ = new NetworkMiddlewareService(address(networkRegistry_));
        OptInService operatorVaultOptInService_ = new OptInService(address(operatorRegistry_), address(vaultFactory_));
        OptInService operatorNetworkOptInService_ =
            new OptInService(address(operatorRegistry_), address(networkRegistry_));

        Vault vault_ = new Vault(address(delegatorFactory_), address(slasherFactory_), address(vaultFactory_));
        vaultFactory_.whitelist(address(vault_));

        address networkRestakeDelegator_ = address(
            new NetworkRestakeDelegator(
                address(networkRegistry_),
                address(vaultFactory_),
                address(operatorVaultOptInService_),
                address(operatorNetworkOptInService_),
                address(delegatorFactory_),
                delegatorFactory_.totalTypes()
            )
        );
        delegatorFactory_.whitelist(networkRestakeDelegator_);

        address fullRestakeDelegator_ = address(
            new FullRestakeDelegator(
                address(networkRegistry_),
                address(vaultFactory_),
                address(operatorVaultOptInService_),
                address(operatorNetworkOptInService_),
                address(delegatorFactory_),
                delegatorFactory_.totalTypes()
            )
        );
        delegatorFactory_.whitelist(fullRestakeDelegator_);

        address slasher_ = address(
            new Slasher(
                address(vaultFactory_),
                address(networkMiddlewareService_),
                address(slasherFactory_),
                slasherFactory_.totalTypes()
            )
        );
        slasherFactory_.whitelist(slasher_);

        address vetoSlasher_ = address(
            new VetoSlasher(
                address(vaultFactory_),
                address(networkMiddlewareService_),
                address(networkRegistry_),
                address(slasherFactory_),
                slasherFactory_.totalTypes()
            )
        );
        slasherFactory_.whitelist(vetoSlasher_);

        VaultConfigurator vaultConfigurator_ =
            new VaultConfigurator(address(vaultFactory_), address(delegatorFactory_), address(slasherFactory_));

        vaultFactory_.transferOwnership(owner);
        delegatorFactory_.transferOwnership(owner);
        slasherFactory_.transferOwnership(owner);

        Token token_ = new Token("Token");
        SimpleCollateral collateral_ = new SimpleCollateral(address(token_));

        vm.stopPrank();

        return (
            vaultFactory_,
            delegatorFactory_,
            slasherFactory_,
            networkRegistry_,
            operatorRegistry_,
            operatorMetadataService_,
            networkMetadataService_,
            networkMiddlewareService_,
            operatorVaultOptInService_,
            operatorNetworkOptInService_,
            vaultConfigurator_,
            collateral_
        );
    }
}
