// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {BoltRegistry} from "../src/contracts/BoltRegistry.sol";
import {IBoltRegistry} from "../src/interfaces/IBoltRegistry.sol";

contract BoltRegistryTest is Test {
    BoltRegistry public registry;

    address alice = address(0x1);
    address bob = address(0x2);

    function setUp() public {
        registry = new BoltRegistry();
    }

    function testAddBasedProposerToRegistry() public {
        vm.prank(alice);
        registry.optIn();

        assertEq(uint8(registry.getBasedProposerStatus(alice)), uint8(IBoltRegistry.BoltStatus.Active));
        assertEq(registry.isActiveBasedProposer(alice), true);
    }

    // TODO: test opt out flow
}
