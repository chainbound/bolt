// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";

/// @notice Script to deploy the BoltManager and BoltValidators contracts.
contract DeployBoltManager is Script {
    function run() public {
        vm.startBroadcast();

        address sender = msg.sender;

        BoltValidators validators = new BoltValidators(sender);
        console.log("BoltValidators deployed at", address(validators));

        address symbioticNetwork = address(0x1);

        BoltManager manager = new BoltManager(address(validators), symbioticNetwork);
        console.log("BoltManager deployed at", address(manager));

        vm.stopBroadcast();
    }
}
