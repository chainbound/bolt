// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Upgrades} from "@openzeppelin-foundry-upgrades/src/Upgrades.sol";

import {BoltParameters} from "../../../src/contracts/BoltParameters.sol";
import {BoltValidators} from "../../../src/contracts/BoltValidators.sol";
import {BoltManager} from "../../../src/contracts/BoltManager.sol";
import {BoltEigenLayerMiddleware} from "../../../src/contracts/BoltEigenLayerMiddleware.sol";
import {BoltSymbioticMiddleware} from "../../../src/contracts/BoltSymbioticMiddleware.sol";
import {BoltConfig} from "../../../src/lib/Config.sol";

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

        BoltConfig.ParametersConfig memory config = readParameters();

        bytes memory initParameters = abi.encodeCall(
            BoltParameters.initialize,
            (
                admin,
                config.epochDuration,
                config.slashingWindow,
                config.maxChallengeDuration,
                config.allowUnsafeRegistration,
                config.challengeBond,
                config.blockhashEvmLookback,
                config.justificationDelay,
                config.eth2GenesisTimestamp,
                config.slotTime,
                config.minimumOperatorStake
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

    function readParameters() public view returns (BoltConfig.ParametersConfig memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/config.holesky.json");
        string memory json = vm.readFile(path);

        uint48 epochDuration = uint48(vm.parseJsonUint(json, ".epochDuration"));
        uint48 slashingWindow = uint48(vm.parseJsonUint(json, ".slashingWindow"));
        uint48 maxChallengeDuration = uint48(vm.parseJsonUint(json, ".maxChallengeDuration"));
        bool allowUnsafeRegistration = vm.parseJsonBool(json, ".allowUnsafeRegistration");
        uint256 challengeBond = vm.parseJsonUint(json, ".challengeBond");
        uint256 blockhashEvmLookback = vm.parseJsonUint(json, ".blockhashEvmLookback");
        uint256 justificationDelay = vm.parseJsonUint(json, ".justificationDelay");
        uint256 eth2GenesisTimestamp = vm.parseJsonUint(json, ".eth2GenesisTimestamp");
        uint256 slotTime = vm.parseJsonUint(json, ".slotTime");
        uint256 minimumOperatorStake = vm.parseJsonUint(json, ".minimumOperatorStake");

        return BoltConfig.ParametersConfig({
            epochDuration: epochDuration,
            slashingWindow: slashingWindow,
            maxChallengeDuration: maxChallengeDuration,
            challengeBond: challengeBond,
            blockhashEvmLookback: blockhashEvmLookback,
            justificationDelay: justificationDelay,
            eth2GenesisTimestamp: eth2GenesisTimestamp,
            slotTime: slotTime,
            allowUnsafeRegistration: allowUnsafeRegistration,
            minimumOperatorStake: minimumOperatorStake
        });
    }
}
