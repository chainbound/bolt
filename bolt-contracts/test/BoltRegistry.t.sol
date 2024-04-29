// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {BoltRegistry} from "../src/BoltRegistry.sol";

contract BoltRegistryTest is Test {
    BoltRegistry public registry;

    address alice = address(0x1);
    address bob = address(0x2);

    function setUp() public {
        registry = new BoltRegistry();
    }

    function testAddPreconfirmer() public {
        registry.addPreconfirmer(alice);
        
        assertEq(uint8(registry.getPreconfirmerStatus(alice)), uint8(BoltRegistry.PreconfirmerStatus.Active));
    }
}
