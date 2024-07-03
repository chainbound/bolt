// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

import {BoltRegistry} from "../src/contracts/BoltRegistry.sol";
import {BoltChallenger} from "../src/contracts/BoltChallenger.sol";

contract DeployRegistry is Script {
    uint256 public signerKey;

    function run() public {
        signerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(signerKey);

        BoltRegistry registry = new BoltRegistry(10 ether);
        console.log("BoltRegistry deployed at", address(registry));

        vm.stopBroadcast();
    }
}
