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
import {IMetadataService} from "@symbiotic/interfaces/service/IMetadataService.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {ISlasherFactory} from "@symbiotic/interfaces/ISlasherFactory.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {IDelegatorFactory} from "@symbiotic/interfaces/IDelegatorFactory.sol";
import {IMigratablesFactory} from "@symbiotic/interfaces/common/IMigratablesFactory.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {SimpleCollateral} from "@symbiotic/../test/mocks/SimpleCollateral.sol";

import {IBoltValidators} from "../src/interfaces/IBoltValidators.sol";
import {IBoltMiddleware} from "../src/interfaces/IBoltMiddleware.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";
import {BoltSymbioticMiddleware} from "../src/contracts/BoltSymbioticMiddleware.sol";
import {BLS12381} from "../src/lib/bls/BLS12381.sol";

import {SymbioticSetupFixture} from "./fixtures/SymbioticSetup.f.sol";

contract BoltManagerSymbioticTest is Test {
    using BLS12381 for BLS12381.G1Point;
    using Subnetwork for address;

    uint48 public constant EPOCH_DURATION = 1 days;
    uint48 public constant SLASHING_WINDOW = 7 days;

    uint128 public constant PRECONF_MAX_GAS_LIMIT = 5_000_000;

    BoltValidators public validators;
    BoltManager public manager;
    BoltSymbioticMiddleware public middleware;

    IVaultFactory public vaultFactory;
    IDelegatorFactory public delegatorFactory;
    ISlasherFactory public slasherFactory;
    INetworkRegistry public networkRegistry;
    IOperatorRegistry public operatorRegistry;
    IMetadataService public operatorMetadataService;
    IMetadataService public networkMetadataService;
    INetworkMiddlewareService public networkMiddlewareService;
    IOptInService public operatorVaultOptInService;
    IOptInService public operatorNetworkOptInService;
    IVetoSlasher public vetoSlasher;
    IVault public vault;
    INetworkRestakeDelegator public networkRestakeDelegator;
    IVaultConfigurator public vaultConfigurator;
    SimpleCollateral public collateral;

    address deployer = makeAddr("deployer");
    address admin = makeAddr("admin");
    address provider = makeAddr("provider");
    address operator = makeAddr("operator");
    address validator = makeAddr("validator");
    address networkAdmin = makeAddr("networkAdmin");
    address vaultAdmin = makeAddr("vaultAdmin");
    address user = makeAddr("user");

    uint96 subnetworkId = 0;
    bytes32 subnetwork = networkAdmin.subnetwork(subnetworkId);

    function setUp() public {
        // fast forward a few days to avoid timestamp underflows
        vm.warp(block.timestamp + SLASHING_WINDOW * 3);

        // --- Deploy Symbiotic contracts ---
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
            vaultConfigurator,
            collateral
        ) = new SymbioticSetupFixture().setUp(deployer, admin);

        // --- Create vault ---

        address[] memory adminRoleHolders = new address[](1);
        adminRoleHolders[0] = vaultAdmin;

        IVaultConfigurator.InitParams memory vaultConfiguratorInitParams = IVaultConfigurator.InitParams({
            version: IMigratablesFactory(vaultConfigurator.VAULT_FACTORY()).lastVersion(),
            owner: vaultAdmin,
            vaultParams: IVault.InitParams({
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
            }),
            delegatorIndex: 0, // Use NetworkRestakeDelegator
            delegatorParams: abi.encode(
                INetworkRestakeDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: vaultAdmin,
                        hook: address(0), // we don't need a hook
                        hookSetRoleHolder: vaultAdmin
                    }),
                    networkLimitSetRoleHolders: adminRoleHolders,
                    operatorNetworkSharesSetRoleHolders: adminRoleHolders
                })
            ),
            withSlasher: true,
            slasherIndex: 1, // Use VetoSlasher
            slasherParams: abi.encode(
                IVetoSlasher.InitParams({
                    // veto duration must be smaller than epoch duration
                    vetoDuration: uint48(12 hours),
                    resolverSetEpochsDelay: 3
                })
            )
        });

        (address vault_, address networkRestakeDelegator_, address vetoSlasher_) =
            vaultConfigurator.create(vaultConfiguratorInitParams);
        vault = IVault(vault_);
        networkRestakeDelegator = INetworkRestakeDelegator(networkRestakeDelegator_);
        vetoSlasher = IVetoSlasher(vetoSlasher_);

        assertEq(address(networkRestakeDelegator), address(vault.delegator()));
        assertEq(address(vetoSlasher), address(vault.slasher()));
        assertEq(address(vault.collateral()), address(collateral));
        assertEq(vault.epochDuration(), EPOCH_DURATION);

        // --- Deploy Bolt contracts ---

        validators = new BoltValidators();
        validators.initialize(admin);
        manager = new BoltManager();
        manager.initialize(admin, address(validators));

        middleware = new BoltSymbioticMiddleware();

        middleware.initialize(
            admin,
            address(manager),
            networkAdmin,
            address(operatorRegistry),
            address(operatorNetworkOptInService),
            address(vaultFactory)
        );

        // --- Whitelist collateral in BoltSymbioticMiddleware ---
        vm.startPrank(admin);
        middleware.addWhitelistedCollateral(address(collateral));
        manager.addRestakingProtocol(address(middleware));
        vm.stopPrank();
    }

    /// @notice Internal helper to register Symbiotic contracts and opt-in operators and vaults.
    /// Should be called inside other tests that need a common setup beyond the default setUp().
    function _symbioticOptInRoutine() internal {
        // --- Register Network and Middleware in Symbiotic ---

        vm.prank(networkAdmin);
        networkRegistry.registerNetwork();

        vm.prank(networkAdmin);
        networkMiddlewareService.setMiddleware(address(middleware));

        // --- Register Validator in BoltValidators ---

        // pubkeys aren't checked, any point will be fine
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(validator);
        validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, operator);
        assertEq(validators.getValidatorByPubkey(pubkey).exists, true);
        assertEq(validators.getValidatorByPubkey(pubkey).authorizedOperator, operator);

        // --- Register Operator in Symbiotic, opt-in network and vault ---

        vm.prank(operator);
        operatorRegistry.registerOperator();
        assertEq(operatorRegistry.isEntity(operator), true);

        vm.prank(operator);
        operatorNetworkOptInService.optIn(networkAdmin);
        assertEq(operatorNetworkOptInService.isOptedIn(operator, networkAdmin), true);

        vm.prank(operator);
        operatorVaultOptInService.optIn(address(vault));
        assertEq(operatorVaultOptInService.isOptedIn(operator, address(vault)), true);

        // --- Register Vault and Operator in BoltManager (middleware) ---

        middleware.registerVault(address(vault));
        assertEq(middleware.isVaultEnabled(address(vault)), true);

        vm.prank(operator);
        middleware.registerOperator("https://bolt-rpc.io");
        assertEq(manager.isOperatorEnabled(operator), true);

        // --- Set the stake limit for the Vault ---

        vm.prank(networkAdmin);
        networkRestakeDelegator.setMaxNetworkLimit(subnetworkId, 10 ether);

        vm.prank(vaultAdmin);
        networkRestakeDelegator.setNetworkLimit(subnetwork, 2 ether);

        // --- Add stake to the Vault ---

        vm.prank(provider);
        SimpleCollateral(collateral).mint(1 ether);

        vm.prank(provider);
        SimpleCollateral(collateral).approve(address(vault), 1 ether);

        // deposit collateral from "provider" on behalf of "operator"
        vm.prank(provider);
        (uint256 depositedAmount, uint256 mintedShares) = vault.deposit(operator, 1 ether);

        assertEq(depositedAmount, 1 ether);
        assertEq(mintedShares, 1 ether);
        assertEq(vault.balanceOf(operator), 1 ether);
        assertEq(SimpleCollateral(collateral).balanceOf(address(vault)), 1 ether);
    }

    /// @notice Compute the hash of a BLS public key
    function _pubkeyHash(
        BLS12381.G1Point memory pubkey
    ) internal pure returns (bytes32) {
        uint256[2] memory compressedPubKey = pubkey.compress();
        return keccak256(abi.encodePacked(compressedPubKey));
    }

    function testReadOperatorStake() public {
        _symbioticOptInRoutine();

        // --- Read the operator stake ---

        // initial state
        uint256 shares = networkRestakeDelegator.totalOperatorNetworkShares(subnetwork);
        uint256 stakeFromDelegator = networkRestakeDelegator.stake(subnetwork, operator);
        uint256 stakeFromMiddleware = middleware.getOperatorStake(operator, address(collateral));
        assertEq(shares, 0);
        assertEq(stakeFromMiddleware, stakeFromDelegator);
        assertEq(stakeFromMiddleware, 0);

        vm.warp(block.timestamp + EPOCH_DURATION + 1);
        assertEq(vault.currentEpoch(), 1);

        // after an epoch has passed
        assertEq(vault.totalStake(), 1 ether);
        assertEq(vault.activeStake(), 1 ether);
        assertEq(vault.activeBalanceOf(operator), 1 ether);
        assertEq(vault.activeSharesAt(uint48(0), ""), 0);
        assertEq(vault.activeSharesAt(uint48(block.timestamp), ""), 1 ether);

        // there still aren't any shares minted on the delegator
        assertEq(networkRestakeDelegator.totalOperatorNetworkShares(subnetwork), 0);
        assertEq(networkRestakeDelegator.operatorNetworkShares(subnetwork, operator), 0);

        // we need to mint shares from the vault admin to activate stake
        // for the operator in the subnetwork.
        vm.prank(vaultAdmin);
        networkRestakeDelegator.setOperatorNetworkShares(subnetwork, operator, 100);
        assertEq(networkRestakeDelegator.totalOperatorNetworkShares(subnetwork), 100);
        assertEq(networkRestakeDelegator.operatorNetworkShares(subnetwork, operator), 100);

        vm.warp(block.timestamp + EPOCH_DURATION + 1);
        assertEq(vault.currentEpoch(), 2);

        // it takes 2 epochs to activate the stake
        // TODO:
        // assertEq(middleware.getTotalStake(0, address(collateral)), 0);
        // assertEq(middleware.getTotalStake(1, address(collateral)), 0);
        // assertEq(middleware.getTotalStake(2, address(collateral)), 1 ether);

        stakeFromDelegator = networkRestakeDelegator.stake(subnetwork, operator);
        stakeFromMiddleware = middleware.getOperatorStake(operator, address(collateral));
        assertEq(stakeFromDelegator, stakeFromMiddleware);
        assertEq(stakeFromMiddleware, 1 ether);
    }

    function testGetProposerStatus() public {
        _symbioticOptInRoutine();

        // we need to mint shares from the vault admin to activate stake
        // for the operator in the subnetwork.
        vm.prank(vaultAdmin);
        networkRestakeDelegator.setOperatorNetworkShares(subnetwork, operator, 100);
        assertEq(networkRestakeDelegator.totalOperatorNetworkShares(subnetwork), 100);
        assertEq(networkRestakeDelegator.operatorNetworkShares(subnetwork, operator), 100);

        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();
        bytes32 pubkeyHash = _pubkeyHash(pubkey);

        vm.warp(block.timestamp + EPOCH_DURATION * 2 + 1);
        assertEq(vault.currentEpoch(), 2);

        IBoltValidators.ProposerStatus memory status = manager.getProposerStatus(pubkeyHash);
        assertEq(status.pubkeyHash, pubkeyHash);
        assertEq(status.operator, operator);
        assertEq(status.active, true);
        assertEq(status.collaterals.length, 1);
        assertEq(status.amounts.length, 1);
        assertEq(status.collaterals[0], address(collateral));
        assertEq(status.amounts[0], 1 ether);
    }

    function testProposersLookaheadStatus() public {
        _symbioticOptInRoutine();

        bytes32[] memory pubkeyHashes = new bytes32[](10);

        // register 10 proposers with random pubkeys
        for (uint256 i = 0; i < 10; i++) {
            BLS12381.G1Point memory pubkey = BLS12381.generatorG1();
            pubkey.x[0] = pubkey.x[0] + i + 2;
            pubkey.y[0] = pubkey.y[0] + i + 2;

            pubkeyHashes[i] = _pubkeyHash(pubkey);
            validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, operator);
        }

        vm.warp(block.timestamp + EPOCH_DURATION * 2 + 1);
        assertEq(vault.currentEpoch(), 2);

        IBoltValidators.ProposerStatus[] memory statuses = manager.getProposersStatus(pubkeyHashes);
        assertEq(statuses.length, 10);
    }

    function testGetNonExistentProposerStatus() public {
        _symbioticOptInRoutine();

        bytes32 pubkeyHash = bytes32(uint256(1));

        vm.expectRevert(IBoltValidators.ValidatorDoesNotExist.selector);
        manager.getProposerStatus(pubkeyHash);
    }

    function testGetWhitelistedCollaterals() public view {
        address[] memory collaterals = middleware.getWhitelistedCollaterals();
        assertEq(collaterals.length, 1);
        assertEq(collaterals[0], address(collateral));
    }

    function testNonWhitelistedCollateral() public {
        vm.prank(admin);
        middleware.removeWhitelistedCollateral(address(collateral));

        vm.prank(vaultAdmin);
        vm.expectRevert(IBoltMiddleware.CollateralNotWhitelisted.selector);
        middleware.registerVault(address(vault));
    }
}
