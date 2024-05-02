// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {BoltRegistry} from "../src/contracts/BoltRegistry.sol";
import {BoltChallenger} from "../src/contracts/BoltChallenger.sol";

contract BoltChallengerTest is Test {
    BoltRegistry public registry;
    BoltChallenger public challenger;

    // Relic protocol contracts
    address relicReliquary = 0x5E4DE6Bb8c6824f29c44Bd3473d44da120387d08;
    address relicBlockHeaderProver = 0x9f9A1eb0CF9340538297c853915DCc06Eb6D72c4;

    address alice = address(0x1);
    address bob = address(0x2);

    function setUp() public {
        registry = new BoltRegistry();
        challenger = new BoltChallenger(address(registry), relicReliquary);
    }
}
