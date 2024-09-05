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
import {ISlasherFactory} from "@symbiotic/interfaces/ISlasherFactory.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {IDelegatorFactory} from "@symbiotic/interfaces/IDelegatorFactory.sol";
import {IMigratablesFactory} from "@symbiotic/interfaces/common/IMigratablesFactory.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";
import {BLS12381} from "../src/lib/bls/BLS12381.sol";

import {Token} from "./mocks/Token.sol";
import {SimpleCollateral} from "./mocks/SimpleCollateral.sol";

import {SymbioticSetupFixture} from "./fixtures/SymbioticSetup.f.sol";

contract BoltManagerTest is Test {
    using BLS12381 for BLS12381.G1Point;
    using Subnetwork for address;

    uint48 public constant EPOCH_DURATION = 1 days;

    BoltValidators public validators;
    BoltManager public manager;

    SimpleCollateral public collateral;

    uint64[] public validatorIndexes;

    address public vaultFactory;
    address public delegatorFactory;
    address public slasherFactory;
    address public networkRegistry;
    address public operatorRegistry;
    address public operatorMetadataService;
    address public networkMetadataService;
    address public networkMiddlewareService;
    address public operatorVaultOptInService;
    address public operatorNetworkOptInService;
    address public vetoSlasher;
    address public vault;
    address public networkRestakeDelegator;
    address public vaultConfigurator;

    address deployer = makeAddr("deployer");
    address admin = makeAddr("admin");
    address provider = makeAddr("provider");
    address operator = makeAddr("operator");
    address validator = makeAddr("validator");
    address networkAdmin = makeAddr("networkAdmin");
    address vaultAdmin = makeAddr("vaultAdmin");

    function setUp() public {
        (
            vaultFactory,
            delegatorFactory,
            slasherFactory,
            networkRegistry,
            operatorRegistry,
            operatorMetadataService,
            networkMetadataService,
            networkMiddlewareService,
            operatorVaultOptInService,
            operatorNetworkOptInService,
            vaultConfigurator
        ) = new SymbioticSetupFixture().setUp(deployer, admin);

        // Deploy collateral token
        vm.startPrank(deployer);
        Token token = new Token("Token");
        collateral = new SimpleCollateral(address(token));
        collateral.mint(token.totalSupply());

        address[] memory adminRoleHolders = new address[](1);
        adminRoleHolders[0] = vaultAdmin;

        IVault.InitParams memory vaultInitParams = IVault.InitParams({
            collateral: address(collateral),
            delegator: address(0),
            slasher: address(0),
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

        IVetoSlasher.InitParams memory vetoSlasherInitParams = IVetoSlasher.InitParams({
            // veto duration must be smaller than epoch duration
            vetoDuration: uint48(12 hours),
            resolverSetEpochsDelay: 3
        });

        IVaultConfigurator.InitParams memory vaultConfiguratorInitParams = IVaultConfigurator.InitParams({
            version: IMigratablesFactory(IVaultConfigurator(vaultConfigurator).VAULT_FACTORY()).lastVersion(),
            owner: vaultAdmin,
            vaultParams: vaultInitParams,
            delegatorIndex: 0, // Use NetworkRestakeDelegator
            delegatorParams: abi.encode(delegatorInitParams),
            withSlasher: true,
            slasherIndex: 1, // Use VetoSlasher
            slasherParams: abi.encode(vetoSlasherInitParams)
        });

        (vault, networkRestakeDelegator, vetoSlasher) =
            IVaultConfigurator(vaultConfigurator).create(vaultConfiguratorInitParams);
        vm.stopPrank();

        assertEq(networkRestakeDelegator, address(IVault(vault).delegator()));
        assertEq(vetoSlasher, address(IVault(vault).slasher()));

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
        bytes32 subnetwork = networkAdmin.subnetwork(0);
        INetworkRestakeDelegator(IVault(vault).delegator()).setNetworkLimit(subnetwork, 1 ether);

        vm.prank(admin);
        IBaseDelegator(IVault(vault).delegator()).setMaxNetworkLimit(0, 1 ether);
    }
}
