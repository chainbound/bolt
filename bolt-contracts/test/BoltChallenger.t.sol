// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {BoltChallenger} from "../src/BoltChallenger.sol";

contract BoltChallengerTest is Test {
    BoltChallenger public challenger;

    address alice = address(0x1);
    address bob = address(0x2);

    function setUp() public {
        challenger = new BoltChallenger();
    }
}
