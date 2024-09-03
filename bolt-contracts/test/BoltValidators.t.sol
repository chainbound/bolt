// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BLS12381} from "../src/lib/bls/BLS12381.sol";

contract BoltValidatorsTest is Test {
    using BLS12381 for BLS12381.G1Point;

    BoltValidators public validators;

    uint64[] public validatorIndexes;

    address admin = address(0x1);
    address provider = address(0x2);
    address operator = address(0x3);
    address validator = address(0x4);

    function setUp() public {
        validators = new BoltValidators(admin);

        // Give some ether to the accounts for gas
        vm.deal(admin, 20 ether);
        vm.deal(provider, 20 ether);
        vm.deal(operator, 20 ether);
        vm.deal(validator, 20 ether);
    }

    function testUnsafeRegistration() public {
        // pubkeys aren't checked, any point will be fine
        BLS12381.G1Point memory pubkey = BLS12381.generatorG1();

        vm.prank(validator);
        validators.registerValidatorUnsafe(pubkey, provider, operator);

        BoltValidators.Validator memory registered = validators.getValidatorByPubkey(pubkey);
        assertEq(registered.exists, true);
        assertEq(registered.authorizedCollateralProvider, provider);
        assertEq(registered.authorizedOperator, operator);
        assertEq(registered.controller, validator);
    }
}
