// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {BoltParametersV1} from "../src/contracts/BoltParametersV1.sol";
import {BoltValidatorsV1} from "../src/contracts/BoltValidatorsV1.sol";
import {IBoltValidatorsV1} from "../src/interfaces/IBoltValidatorsV1.sol";
import {BLS12381} from "../src/lib/bls/BLS12381.sol";
import {BoltConfig} from "../src/lib/Config.sol";
import {Utils} from "./Utils.sol";

contract BoltValidatorsTest is Test {
    using BLS12381 for BLS12381.G1Point;

    BoltParametersV1 public parameters;
    BoltValidatorsV1 public validators;

    uint128 public constant PRECONF_MAX_GAS_LIMIT = 5_000_000;

    address admin = makeAddr("admin");
    address provider = makeAddr("provider");
    address operator = makeAddr("operator");
    address validator = makeAddr("validator");

    function setUp() public {
        BoltConfig.Parameters memory config = new Utils().readParameters();

        parameters = new BoltParametersV1();
        parameters.initialize(
            admin,
            config.epochDuration,
            config.slashingWindow,
            config.maxChallengeDuration,
            config.allowUnsafeRegistration,
            config.challengeBond,
            config.blockhashEvmLookback,
            config.justificationDelay,
            config.eth2GenesisTimestamp,
            config.slotTime,
            config.minimumOperatorStake
        );

        validators = new BoltValidatorsV1();
        validators.initialize(admin, address(parameters));
    }

    function testUnsafeRegistration() public {
        // pubkeys aren't checked, any point will be fine
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(validator);
        validators.registerValidatorUnsafe(pubkey, 1_000_000, operator);

        BoltValidatorsV1.Validator memory registered = validators.getValidatorByPubkey(pubkey);
        assertEq(registered.exists, true);
        assertEq(registered.maxCommittedGasLimit, 1_000_000);
        assertEq(registered.authorizedOperator, operator);
        assertEq(registered.controller, validator);
    }

    function testUnsafeRegistrationFailsIfAlreadyRegistered() public {
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(validator);
        validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, operator);

        vm.prank(validator);
        vm.expectRevert(IBoltValidatorsV1.ValidatorAlreadyExists.selector);
        validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, operator);
    }

    function testUnsafeRegistrationWhenNotAllowed() public {
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(admin);
        parameters.setAllowUnsafeRegistration(false);

        vm.prank(validator);
        vm.expectRevert(IBoltValidatorsV1.UnsafeRegistrationNotAllowed.selector);
        validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, operator);
    }

    function testUnsafeRegistrationInvalidOperator() public {
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(validator);
        vm.expectRevert(IBoltValidatorsV1.InvalidAuthorizedOperator.selector);
        validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, address(0));
    }
}
