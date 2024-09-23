// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";
import {BoltEigenLayerMiddleware} from "../src/contracts/BoltEigenLayerMiddleware.sol";
import {BoltSymbioticMiddleware} from "../src/contracts/BoltSymbioticMiddleware.sol";

/// @notice Script to deploy the BoltManager and BoltValidators contracts.
contract DeployBolt is Script {
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

        BoltManager manager = new BoltManager(sender, address(validators));
        console.log("BoltManager deployed at", address(manager));

        BoltEigenLayerMiddleware eigenLayerMiddleware = new BoltEigenLayerMiddleware(
            sender,
            address(validators),
            eigenlayerAVSDirectory,
            eigenlayerDelegationManager,
            eigenlayerStrategyManager
        );
        console.log("BoltEigenLayerMiddleware deployed at", address(eigenLayerMiddleware));
        BoltSymbioticMiddleware symbioticMiddleware = new BoltSymbioticMiddleware(
            sender,
            address(validators),
            symbioticNetwork,
            symbioticOperatorRegistry,
            symbioticOperatorNetOptIn,
            symbioticVaultRegistry
        );
        vm.stopBroadcast();
    }
}
