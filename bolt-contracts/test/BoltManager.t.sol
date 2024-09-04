// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";
import {IOperatorRegistry} from "@symbiotic/interfaces/IOperatorRegistry.sol";
import {IVaultFactory} from "@symbiotic/interfaces/IVaultFactory.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";
import {BLS12381} from "../src/lib/bls/BLS12381.sol";

import {SymbioticSetupFixture} from "./fixtures/SymbioticSetup.f.sol";

contract BoltManagerTest is Test {
    using BLS12381 for BLS12381.G1Point;

    BoltValidators public validators;
    BoltManager public manager;

    uint64[] public validatorIndexes;

    address public networkRegistry;
    address public operatorRegistry;
    address public vaultFactory;
    address public operatorMetadataService;
    address public networkMetadataService;
    address public networkMiddlewareService;
    address public operatorVaultOptInService;
    address public operatorNetworkOptInService;
    address public vetoSlasherImpl;
    address public vaultImpl;
    address public networkRestakeDelegatorImpl;

    address deployer = address(0x1);
    address admin = address(0x2);
    address provider = address(0x3);
    address operator = address(0x4);
    address validator = address(0x5);
    address networkAdmin = address(0x6);

    function setUp() public {
        // Give some ether to the accounts for gas
        vm.deal(deployer, 200 ether);
        vm.deal(admin, 20 ether);
        vm.deal(provider, 20 ether);
        vm.deal(operator, 20 ether);
        vm.deal(validator, 20 ether);
        vm.deal(networkAdmin, 20 ether);

        // Deploy Symbiotic contracts
        (
            vaultFactory,
            , // delegatorFactory
            , // slasherFactory
            networkRegistry,
            operatorRegistry,
            operatorMetadataService,
            networkMetadataService,
            networkMiddlewareService,
            operatorVaultOptInService,
            operatorNetworkOptInService,
            , // slasherImpl
            vetoSlasherImpl,
            , // vaultConfigurator
            vaultImpl,
            networkRestakeDelegatorImpl,
            // fullRestakeDelegatorImpl
        ) = new SymbioticSetupFixture().setup(deployer, admin);

        // Register the network in Symbiotic
        vm.prank(networkAdmin);
        INetworkRegistry(networkRegistry).registerNetwork();

        // Deploy Bolt contracts
        validators = new BoltValidators(admin);
        manager = new BoltManager(
            address(validators), networkAdmin, operatorRegistry, operatorNetworkOptInService, vaultFactory
        );
    }

    function testFullSymbioticOptIn() public {
        // --- 1. register Validator in BoltValidators ---

        // pubkeys aren't checked, any point will be fine
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(validator);
        validators.registerValidatorUnsafe(pubkey, provider, operator);
        assertEq(validators.getValidatorByPubkey(pubkey).exists, true);
        assertEq(validators.getValidatorByPubkey(pubkey).authorizedOperator, operator);
        assertEq(validators.getValidatorByPubkey(pubkey).authorizedCollateralProvider, provider);

        // --- 2. register Operator in Symbiotic ---

        vm.prank(operator);
        IOperatorRegistry(operatorRegistry).registerOperator();
        assertEq(IOperatorRegistry(operatorRegistry).isEntity(operator), true);

        vm.prank(operator);
        IOptInService(operatorNetworkOptInService).optIn(networkAdmin);
        assertEq(IOptInService(operatorNetworkOptInService).isOptedIn(operator, networkAdmin), true);

        // --- 3. register Operator in BoltManager ---

        manager.registerSymbioticOperator(operator);
        assertEq(manager.isSymbioticOperatorEnabled(operator), true);

        // --- 4. set the stake limit for the Vault ---

        vm.prank(admin);
        INetworkRestakeDelegator(networkRestakeDelegatorImpl).setNetworkLimit(0, 1 ether);

        vm.prank(admin);
        IBaseDelegator(IVault(vaultImpl).delegator()).setMaxNetworkLimit(0, 1 ether);
    }
}
