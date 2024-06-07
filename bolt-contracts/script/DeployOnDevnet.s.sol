// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

import {BoltRegistry} from "../src/contracts/BoltRegistry.sol";
import {BoltChallenger} from "../src/contracts/BoltChallenger.sol";

contract DeployOnDevnet is Script {
    function setUp() public {}

    function run() public {
        // Relic protocol contracts
        address relicReliquary = 0x5E4DE6Bb8c6824f29c44Bd3473d44da120387d08;
        address relicBlockHeaderProver = 0x9f9A1eb0CF9340538297c853915DCc06Eb6D72c4;
        address relicAccountInfoProver = 0xf74105AE736Ca0C4B171a2EC4F1D4B0b6EBB99ae;

        vm.startBroadcast();

        BoltRegistry registry = new BoltRegistry();
        console.log("BoltRegistry deployed at", address(registry));

        BoltChallenger challenger =
            new BoltChallenger(address(registry), relicReliquary, relicBlockHeaderProver, relicAccountInfoProver);
        console.log("BoltChallenger deployed at", address(challenger));

        vm.stopBroadcast();
    }
}
