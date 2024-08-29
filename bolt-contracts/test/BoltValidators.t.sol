// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {BoltValidators} from "../src/contracts/BoltValidators.sol";

contract BoltValidatorsTest is Test {
    BoltValidators public validators;

    uint64[] public validatorIndexes;

    address provider = address(0x1);
    address operator = address(0x2);
    address validator = address(0x3);

    function setUp() public {
        validators = new BoltValidators();

        // Give some ether to the accounts for gas
        vm.deal(provider, 20 ether);
        vm.deal(operator, 20 ether);
        vm.deal(validator, 20 ether);
    }

    function testRegistration() public {
        // TODO
    }
}
