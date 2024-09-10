// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {BoltRegistry} from "../src/contracts/BoltRegistry.sol";
import {IBoltRegistry} from "../src/interfaces/IBoltRegistry.sol";

contract BoltRegistryTest is Test {
    BoltRegistry public registry;

    uint64[] public validatorIndexes;

    address alice = address(0x1);
    address bob = address(0x2);

    function setUp() public {
        registry = new BoltRegistry(10 ether);
        vm.deal(alice, 20 ether);
    }

    function testRegistration() public {
        vm.prank(alice);

        validatorIndexes.push(1);
        validatorIndexes.push(2);
        validatorIndexes.push(3);

        registry.register{value: 10 ether}(validatorIndexes, "rpc", "");

        assertEq(uint8(registry.getOperatorStatus(alice)), uint8(IBoltRegistry.Status.ACTIVE));

        assertEq(registry.isActiveOperator(alice), true);

        assertEq(registry.getOperatorForValidator(1).operator, alice);
        assertEq(registry.getOperatorForValidator(1).metadata.rpc, "rpc");
    }

    // function testOptOut() public {
    //     assertEq(registry.isActiveBasedProposer(alice), false);
    //     vm.expectRevert(IBoltRegistry.BasedProposerDoesNotExist.selector);
    //     registry.getBasedProposerStatus(alice);

    //     vm.prank(alice);
    //     registry.optIn();
    //     assertEq(registry.isActiveBasedProposer(alice), true);
    //     assertEq(
    //         uint8(registry.getBasedProposerStatus(alice)),
    //         uint8(IBoltRegistry.BoltStatus.Active)
    //     );

    //     vm.prank(alice);
    //     registry.beginOptOut();

    //     assertEq(registry.isActiveBasedProposer(alice), true);
    //     assertEq(
    //         uint8(registry.getBasedProposerStatus(alice)),
    //         uint8(IBoltRegistry.BoltStatus.Active)
    //     );

    //     // check that confirmation can't be done immediately
    //     vm.expectRevert(IBoltRegistry.CooldownNotElapsed.selector);
    //     vm.prank(alice);
    //     registry.confirmOptOut();

    //     // wait 1 day
    //     vm.warp(block.timestamp + 1 days);

    //     // check that opt out can be confirmed
    //     vm.prank(alice);
    //     vm.expectEmit(address(registry));
    //     emit IBoltRegistry.BasedProposerStatusChanged(
    //         alice,
    //         IBoltRegistry.BoltStatus.Inactive
    //     );
    //     registry.confirmOptOut();

    //     assertEq(registry.isActiveBasedProposer(alice), false);
    //     assertEq(
    //         uint8(registry.getBasedProposerStatus(alice)),
    //         uint8(IBoltRegistry.BoltStatus.Inactive)
    //     );

    //     // check that opt out can't be confirmed again
    //     vm.expectRevert(IBoltRegistry.InvalidStatusChange.selector);
    //     vm.prank(alice);
    //     registry.confirmOptOut();
    // }
}
