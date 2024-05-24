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

    function testOptIn() public {
        vm.prank(alice);
        registry.optIn();

        assertEq(uint8(registry.getBasedProposerStatus(alice)), uint8(IBoltRegistry.BoltStatus.Active));
        assertEq(registry.isActiveBasedProposer(alice), true);
    }

    function testOptOut() public {
        assertEq(registry.isActiveBasedProposer(alice), false);
        vm.expectRevert(IBoltRegistry.BasedProposerDoesNotExist.selector);
        registry.getBasedProposerStatus(alice);

        vm.prank(alice);
        registry.optIn();
        assertEq(registry.isActiveBasedProposer(alice), true);
        assertEq(uint8(registry.getBasedProposerStatus(alice)), uint8(IBoltRegistry.BoltStatus.Active));

        vm.prank(alice);
        registry.beginOptOut();

        assertEq(registry.isActiveBasedProposer(alice), true);
        assertEq(uint8(registry.getBasedProposerStatus(alice)), uint8(IBoltRegistry.BoltStatus.Active));

        // check that confirmation can't be done immediately
        vm.expectRevert(IBoltRegistry.CooldownNotElapsed.selector);
        vm.prank(alice);
        registry.confirmOptOut();

        // wait 1 day
        vm.warp(block.timestamp + 1 days);

        // check that opt out can be confirmed
        vm.prank(alice);
        vm.expectEmit(address(registry));
        emit IBoltRegistry.BasedProposerStatusChanged(alice, IBoltRegistry.BoltStatus.Inactive);
        registry.confirmOptOut();

        assertEq(registry.isActiveBasedProposer(alice), false);
        assertEq(uint8(registry.getBasedProposerStatus(alice)), uint8(IBoltRegistry.BoltStatus.Inactive));

        // check that opt out can't be confirmed again
        vm.expectRevert(IBoltRegistry.InvalidStatusChange.selector);
        vm.prank(alice);
        registry.confirmOptOut();
    }
}
