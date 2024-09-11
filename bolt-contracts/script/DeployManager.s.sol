// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";

/// @notice Script to deploy the BoltManager and BoltValidators contracts.
contract DeployBoltManager is Script {
    function run(
        address symbioticNetwork,
        address symbioticOperatorRegistry,
        address symbioticOperatorNetOptIn,
        address symbioticVaultRegistry,
        address eigenlayerAVSDirectory,
        address eigenlayerDelegationManager,
        address eigenlayerStrategyManager
    ) public {
        vm.startBroadcast();

        address sender = msg.sender;

        BoltValidators validators = new BoltValidators(sender);
        console.log("BoltValidators deployed at", address(validators));

        BoltManager manager = new BoltManager(
            address(sender),
            address(validators),
            symbioticNetwork,
            symbioticOperatorRegistry,
            symbioticOperatorNetOptIn,
            symbioticVaultRegistry,
            eigenlayerAVSDirectory,
            eigenlayerDelegationManager,
            eigenlayerStrategyManager
        );
        console.log("BoltManager deployed at", address(manager));

        vm.stopBroadcast();
    }
}
