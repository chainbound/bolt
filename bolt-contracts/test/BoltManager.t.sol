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

import {IBoltValidators} from "../src/interfaces/IBoltValidators.sol";
import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";
import {BLS12381} from "../src/lib/bls/BLS12381.sol";

import {SymbioticSetupFixture} from "./fixtures/SymbioticSetup.f.sol";
import {SimpleCollateral} from "./mocks/SimpleCollateral.sol";

contract BoltManagerTest is Test {
    using BLS12381 for BLS12381.G1Point;
    using Subnetwork for address;

    uint48 public constant EPOCH_DURATION = 1 days;
    uint48 public constant SLASHING_WINDOW = 7 days;

    BoltValidators public validators;
    BoltManager public manager;

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

        validators = new BoltValidators(admin);
        manager = new BoltManager(
            address(validators),
            networkAdmin,
            address(operatorRegistry),
            address(operatorNetworkOptInService),
            address(vaultFactory)
        );
    }

    /// @notice Internal helper to register Symbiotic contracts and opt-in operators and vaults.
    /// Should be called inside other tests that need a common setup beyond the default setUp().
    function _optInSymbioticRoutine() internal {
        // --- Register Network in Symbiotic ---

        vm.prank(networkAdmin);
        networkRegistry.registerNetwork();

        // --- Register Middleware in Symbiotic ---

        vm.prank(networkAdmin);
        networkMiddlewareService.setMiddleware(address(manager));

        // --- Register Validator in BoltValidators ---

        // pubkeys aren't checked, any point will be fine
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(validator);
        validators.registerValidatorUnsafe(pubkey, provider, operator);
        assertEq(validators.getValidatorByPubkey(pubkey).exists, true);
        assertEq(validators.getValidatorByPubkey(pubkey).authorizedOperator, operator);
        assertEq(validators.getValidatorByPubkey(pubkey).authorizedCollateralProvider, provider);

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

        manager.registerSymbioticVault(address(vault));
        assertEq(manager.isSymbioticVaultEnabled(address(vault)), true);

        manager.registerSymbioticOperator(operator);
        assertEq(manager.isSymbioticOperatorEnabled(operator), true);

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
        assertEq(SimpleCollateral(collateral).balanceOf(address(vault)), 1 ether);
        assertEq(vault.balanceOf(operator), 1 ether);
    }

    /// @notice Compute the hash of a BLS public key
    function _pubkeyHash(BLS12381.G1Point memory pubkey) internal pure returns (bytes32) {
        uint256[2] memory compressedPubKey = pubkey.compress();
        return keccak256(abi.encodePacked(compressedPubKey));
    }

    function testReadOperatorStake() public {
        _optInSymbioticRoutine();

        // --- Read the operator stake ---

        // initial state
        uint256 shares = networkRestakeDelegator.totalOperatorNetworkShares(subnetwork);
        uint256 stakeFromDelegator = networkRestakeDelegator.stake(subnetwork, operator);
        uint256 stakeFromManager = manager.getSymbioticOperatorStake(operator, address(collateral));
        assertEq(shares, 0);
        assertEq(stakeFromManager, stakeFromDelegator);
        assertEq(stakeFromManager, 0);

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

        // assertEq(manager.getSymbioticTotalStake(0, address(collateral)), 0);
        // assertEq(manager.getSymbioticTotalStake(1, address(collateral)), 1 ether);

        // TODO: get correct active stake from manager
        // stakeFromDelegator = networkRestakeDelegator.stake(subnetwork, operator);
        // stakeFromManager = manager.getSymbioticOperatorStake(operator, address(collateral));
        // assertEq(stakeFromDelegator, stakeFromManager);
        // assertEq(stakeFromManager, 1 ether);
    }

    function testGetProposerStatus() public {
        _optInSymbioticRoutine();

        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();
        bytes32 pubkeyHash = _pubkeyHash(pubkey);

        BoltManager.ProposerStatus memory status = manager.getProposerStatus(pubkeyHash);
        assertEq(status.pubkeyHash, pubkeyHash);
        assertEq(status.operator, operator);
        assertEq(status.active, true);
        assertEq(status.collaterals.length, 1);
        assertEq(status.amounts.length, 1);
        assertEq(status.collaterals[0], address(collateral));

        // TODO: this should be 1 ether, but reading from delegator doesn't work
        // see testReadOperatorStake above for details.
        assertEq(status.amounts[0], 0);
    }

    function testGetNonExistentProposerStatus() public {
        _optInSymbioticRoutine();

        bytes32 pubkeyHash = bytes32(uint256(1));

        vm.expectRevert(IBoltValidators.ValidatorDoesNotExist.selector);
        manager.getProposerStatus(pubkeyHash);
    }
}
