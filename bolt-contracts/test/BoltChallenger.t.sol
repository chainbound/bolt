// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {BoltRegistry} from "../src/contracts/BoltRegistry.sol";
import {BoltChallenger} from "../src/contracts/BoltChallenger.sol";

contract BoltChallengerTest is Test {
    BoltRegistry public registry;
    BoltChallenger public challenger;

    address alice = address(0x1);
    address bob = address(0x2);

    function setUp() public {
        registry = new BoltRegistry();
        challenger = new BoltChallenger(address(registry));
    }
}
