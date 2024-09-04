// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";
import {IOperatorRegistry} from "@symbiotic/interfaces/IOperatorRegistry.sol";
import {IVaultFactory} from "@symbiotic/interfaces/IVaultFactory.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";
import {BLS12381} from "../src/lib/bls/BLS12381.sol";

import {SymbioticSetupFixture} from "./fixtures/SymbioticSetup.f.sol";

contract BoltManagerTest is Test {
    using BLS12381 for BLS12381.G1Point;

    uint48 public constant EPOCH_DURATION = 1 days;

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
    address public slasherImpl;
    address public vetoSlasherImpl;
    address public vaultConfigurator;
    address public vaultImpl;
    address public networkRestakeDelegatorImpl;

    address deployer = makeAddr("deployer");
    address admin = makeAddr("admin");
    address provider = makeAddr("provider");
    address operator = makeAddr("operator");
    address validator = makeAddr("validator");
    address networkAdmin = makeAddr("networkAdmin");
    address vaultAdmin = makeAddr("vaultAdmin");

    // TODO: Deploy a real Symbiotic collateral contract
    address collateral = makeAddr("collateral");

    function setUp() public {
        // Give some ether to the accounts for gas
        vm.deal(deployer, 200 ether);
        vm.deal(admin, 20 ether);
        vm.deal(provider, 20 ether);
        vm.deal(operator, 20 ether);
        vm.deal(validator, 20 ether);
        vm.deal(networkAdmin, 20 ether);
        vm.deal(vaultAdmin, 20 ether);

        // Deploy Symbiotic core contracts
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
            slasherImpl,
            vetoSlasherImpl,
            vaultConfigurator,
            networkRestakeDelegatorImpl,
            // fullRestakeDelegatorImpl
        ) = new SymbioticSetupFixture().setUp(deployer, admin);

        address[] memory adminRoleHolders = new address[](1);
        adminRoleHolders[0] = vaultAdmin;

        IVault.InitParams memory vaultInitParams = IVault.InitParams({
            collateral: collateral,
            delegator: networkRestakeDelegatorImpl,
            slasher: slasherImpl,
            burner: address(0xdead),
            epochDuration: EPOCH_DURATION,
            depositWhitelist: false,
            isDepositLimit: false,
            depositLimit: 0,
            defaultAdminRoleHolder: vaultAdmin,
            depositWhitelistSetRoleHolder: vaultAdmin,
            depositorWhitelistRoleHolder: vaultAdmin,
            isDepositLimitSetRoleHolder: vaultAdmin,
            depositLimitSetRoleHolder: vaultAdmin
        });

        INetworkRestakeDelegator.InitParams memory delegatorInitParams = INetworkRestakeDelegator.InitParams({
            baseParams: IBaseDelegator.BaseParams({
                defaultAdminRoleHolder: vaultAdmin,
                hook: address(0), // we don't need a hook
                hookSetRoleHolder: vaultAdmin
            }),
            networkLimitSetRoleHolders: adminRoleHolders,
            operatorNetworkSharesSetRoleHolders: adminRoleHolders
        });

        IVaultConfigurator.InitParams memory vaultConfiguratorInitParams = IVaultConfigurator.InitParams({
            version: 1,
            owner: vaultAdmin,
            vaultParams: vaultInitParams,
            delegatorIndex: 0,
            delegatorParams: abi.encode(delegatorInitParams),
            withSlasher: false, // TODO: activate slasher and add params
            slasherIndex: 0,
            slasherParams: bytes("")
        });

        (vaultImpl, , ) = IVaultConfigurator(vaultConfigurator).create(vaultConfiguratorInitParams);

        assertEq(networkRestakeDelegatorImpl, address(IVault(vaultImpl).delegator()));
        assertEq(slasherImpl, address(IVault(vaultImpl).slasher()));

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
