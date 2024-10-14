// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Upgrades} from "@openzeppelin-foundry-upgrades/src/Upgrades.sol";

import {BoltParameters} from "../src/contracts/BoltParameters.sol";
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

        uint48 epochDuration = 1 days;
        uint48 slashingWindow = 7 days;
        uint48 maxChallengeDuration = 7 days;
        bool allowUnsafeRegistration = true;
        uint256 challengeBond = 1 ether;
        uint256 blockhashEvmLookback = 256;

        bytes memory initParameters = abi.encodeCall(
            BoltParameters.initialize,
            (
                admin,
                epochDuration,
                slashingWindow,
                maxChallengeDuration,
                allowUnsafeRegistration,
                challengeBond,
                blockhashEvmLookback
            )
        );
        address parametersProxy = Upgrades.deployUUPSProxy("BoltParameters.sol", initParameters);
        console.log("BoltParameters proxy deployed at", parametersProxy);

        // Generate the `initialize` call data for the contract.
        bytes memory initValidators = abi.encodeCall(BoltValidators.initialize, (admin, parametersProxy));
        // Deploy the UUPSProxy through the `Upgrades` library, with the correct `initialize` call data.
        address validatorsProxy = Upgrades.deployUUPSProxy("BoltValidators.sol", initValidators);
        console.log("BoltValidators proxy deployed at", validatorsProxy);

        bytes memory initManager = abi.encodeCall(BoltManager.initialize, (admin, parametersProxy, validatorsProxy));
        address managerProxy = Upgrades.deployUUPSProxy("BoltManager.sol", initManager);
        console.log("BoltManager proxy deployed at", managerProxy);

        bytes memory initEigenLayerMiddleware = abi.encodeCall(
            BoltEigenLayerMiddleware.initialize,
            (
                admin,
                parametersProxy,
                managerProxy,
                eigenlayerAVSDirectory,
                eigenlayerDelegationManager,
                eigenlayerStrategyManager
            )
        );
        address eigenLayerMiddlewareProxy =
            Upgrades.deployUUPSProxy("BoltEigenLayerMiddleware.sol", initEigenLayerMiddleware);
        console.log("BoltEigenLayerMiddleware proxy deployed at", eigenLayerMiddlewareProxy);

        bytes memory initSymbioticMiddleware = abi.encodeCall(
            BoltSymbioticMiddleware.initialize,
            (
                admin,
                parametersProxy,
                managerProxy,
                symbioticNetwork,
                symbioticOperatorRegistry,
                symbioticOperatorNetOptIn,
                symbioticVaultRegistry
            )
        );
        address symbioticMiddlewareProxy =
            Upgrades.deployUUPSProxy("BoltSymbioticMiddleware.sol", initSymbioticMiddleware);
        console.log("BoltSymbioticMiddleware proxy deployed at", address(symbioticMiddlewareProxy));

        vm.stopBroadcast();
    }
}
