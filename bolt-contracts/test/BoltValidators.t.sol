// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {BoltValidators} from "../src/contracts/BoltValidators.sol";

contract BoltValidatorsTest is Test {
    BoltValidators public validators;

    uint64[] public validatorIndexes;

    address admin = address(0x1);
    address provider = address(0x2);
    address operator = address(0x3);
    address validator = address(0x4);

    function setUp() public {
        validators = new BoltValidators(admin);

        // Give some ether to the accounts for gas
        vm.deal(provider, 20 ether);
        vm.deal(operator, 20 ether);
        vm.deal(validator, 20 ether);
    }

    function testRegistration() public {
        // TODO
    }
}
