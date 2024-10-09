// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

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

        // The admin address will be authorized to call the adminOnly functions
        // on the contract implementations, as well as upgrade the contracts.
        address admin = msg.sender;

        // TODO: IMPORTANT: Use a different account for the proxy admin!
        // Otherwise we will not be able to access the adminOnly functions
        // on the underlying implementations through the proxy.
        // We can however call them directly if needed.

        address validatorsImplementation = address(new BoltValidators(admin));
        console.log("BoltValidators implementation deployed at", validatorsImplementation);

        address validatorsProxy = address(new ERC1967Proxy(validatorsImplementation, ""));
        console.log("BoltValidators proxy deployed at", validatorsProxy);

        address managerImplementation = address(new BoltManager(admin, validatorsProxy));
        console.log("BoltManager implementation deployed at", managerImplementation);

        address managerProxy = address(new ERC1967Proxy(managerImplementation, ""));
        console.log("BoltManager proxy deployed at", managerProxy);

        address eigenLayerMiddlewareImplementation = address(
            new BoltEigenLayerMiddleware(
                admin, managerProxy, eigenlayerAVSDirectory, eigenlayerDelegationManager, eigenlayerStrategyManager
            )
        );

        console.log("BoltEigenLayerMiddleware implementation deployed at", eigenLayerMiddlewareImplementation);

        address eigenLayerMiddlewareProxy = address(new ERC1967Proxy(eigenLayerMiddlewareImplementation, ""));
        console.log("BoltEigenLayerMiddleware proxy deployed at", eigenLayerMiddlewareProxy);

        address symbioticMiddleware = address(
            new BoltSymbioticMiddleware(
                admin,
                address(managerProxy),
                symbioticNetwork,
                symbioticOperatorRegistry,
                symbioticOperatorNetOptIn,
                symbioticVaultRegistry
            )
        );
        console.log("BoltSymbioticMiddleware deployed at", address(symbioticMiddleware));

        address symbioticMiddlewareProxy = address(new ERC1967Proxy(symbioticMiddleware, ""));
        console.log("BoltSymbioticMiddleware proxy deployed at", address(symbioticMiddlewareProxy));

        vm.stopBroadcast();
    }
}
