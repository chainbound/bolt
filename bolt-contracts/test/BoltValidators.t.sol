// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {IBoltValidators} from "../src/interfaces/IBoltValidators.sol";
import {BLS12381} from "../src/lib/bls/BLS12381.sol";

contract BoltValidatorsTest is Test {
    using BLS12381 for BLS12381.G1Point;

    BoltValidators public validators;

    uint128 public constant PRECONF_MAX_GAS_LIMIT = 5_000_000;

    address admin = makeAddr("admin");
    address provider = makeAddr("provider");
    address operator = makeAddr("operator");
    address validator = makeAddr("validator");

    function setUp() public {
        validators = new BoltValidators();
        validators.initialize(admin);
    }

    function testUnsafeRegistration() public {
        // pubkeys aren't checked, any point will be fine
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(validator);
        validators.registerValidatorUnsafe(pubkey, 1_000_000, operator);

        BoltValidators.Validator memory registered = validators.getValidatorByPubkey(pubkey);
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
        vm.expectRevert(IBoltValidators.ValidatorAlreadyExists.selector);
        validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, operator);
    }

    function testUnsafeRegistrationWhenNotAllowed() public {
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(admin);
        validators.setAllowUnsafeRegistration(false);

        vm.prank(validator);
        vm.expectRevert(IBoltValidators.UnsafeRegistrationNotAllowed.selector);
        validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, operator);
    }

    function testUnsafeRegistrationInvalidOperator() public {
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(validator);
        vm.expectRevert(IBoltValidators.InvalidAuthorizedOperator.selector);
        validators.registerValidatorUnsafe(pubkey, PRECONF_MAX_GAS_LIMIT, address(0));
    }
}
