// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";

/// @notice Script to deploy the BoltManager and BoltValidators contracts.
contract DeployBoltManager is Script {
    uint256 public signerKey;

    function run() public {
        signerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(signerKey);

        BoltValidators validators = new BoltValidators();
        console.log("BoltValidators deployed at", address(validators));

        BoltManager manager = new BoltManager(address(validators));
        console.log("BoltManager deployed at", address(manager));

        vm.stopBroadcast();
    }
}
