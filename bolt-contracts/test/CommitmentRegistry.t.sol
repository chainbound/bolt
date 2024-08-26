// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {CommitmentRegistry} from "../src/contracts/CommitmentRegistry.sol";

contract CommitmentRegistryTest is Test {
    CommitmentRegistry public registry;

    uint64[] public validatorIndexes;

    address provider = address(0x1);
    address operator = address(0x2);
    address validator = address(0x3);

    function setUp() public {
        registry = new CommitmentRegistry();

        // Give some ether to the accounts for gas
        vm.deal(provider, 20 ether);
        vm.deal(operator, 20 ether);
        vm.deal(validator, 20 ether);
    }

    function testRegistration() public {
        // TODO
    }
}
