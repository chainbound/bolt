// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Upgrades} from "@openzeppelin-foundry-upgrades/src/Upgrades.sol";

import {BoltParametersV1} from "../../src/contracts/BoltParametersV1.sol";
import {BoltValidatorsV1} from "../../src/contracts/BoltValidatorsV1.sol";
import {BoltManagerV1} from "../../src/contracts/BoltManagerV1.sol";
import {BoltEigenLayerMiddlewareV1} from "../../src/contracts/BoltEigenLayerMiddlewareV1.sol";
import {BoltSymbioticMiddlewareV1} from "../../src/contracts/BoltSymbioticMiddlewareV1.sol";
import {BoltConfig} from "../../src/lib/Config.sol";

/// @notice Script to deploy the Bolt contracts.
contract DeployBolt is Script {
    function run() public {
        vm.startBroadcast();

        // The admin address will be authorized to call the adminOnly functions
        // on the contract implementations, as well as upgrade the contracts.
        address admin = 0xB5d6600D2B4C18E828C5E345Ed094F56d36c3c2F;
        console.log("Deploying with admin", admin);

        BoltConfig.Parameters memory config = readParameters();
        BoltConfig.Deployments memory deployments = readDeployments();

        bytes memory initParameters = abi.encodeCall(
            BoltParametersV1.initialize,
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
        bytes memory initValidators = abi.encodeCall(BoltValidatorsV1.initialize, (admin, parametersProxy));
        // Deploy the UUPSProxy through the `Upgrades` library, with the correct `initialize` call data.
        address validatorsProxy = Upgrades.deployUUPSProxy("BoltValidators.sol", initValidators);
        console.log("BoltValidators proxy deployed at", validatorsProxy);

        bytes memory initManager = abi.encodeCall(BoltManagerV1.initialize, (admin, parametersProxy, validatorsProxy));
        address managerProxy = Upgrades.deployUUPSProxy("BoltManager.sol", initManager);
        console.log("BoltManager proxy deployed at", managerProxy);

        bytes memory initEigenLayerMiddleware = abi.encodeCall(
            BoltEigenLayerMiddlewareV1.initialize,
            (
                admin,
                parametersProxy,
                managerProxy,
                deployments.eigenLayerAVSDirectory,
                deployments.eigenLayerDelegationManager,
                deployments.eigenLayerStrategyManager
            )
        );
        address eigenLayerMiddlewareProxy =
            Upgrades.deployUUPSProxy("BoltEigenLayerMiddleware.sol", initEigenLayerMiddleware);
        console.log("BoltEigenLayerMiddleware proxy deployed at", eigenLayerMiddlewareProxy);

        bytes memory initSymbioticMiddleware = abi.encodeCall(
            BoltSymbioticMiddlewareV1.initialize,
            (
                admin,
                parametersProxy,
                managerProxy,
                deployments.symbioticNetwork,
                deployments.symbioticOperatorRegistry,
                deployments.symbioticOperatorNetOptIn,
                deployments.symbioticVaultFactory
            )
        );
        address symbioticMiddlewareProxy =
            Upgrades.deployUUPSProxy("BoltSymbioticMiddleware.sol", initSymbioticMiddleware);
        console.log("BoltSymbioticMiddleware proxy deployed at", address(symbioticMiddlewareProxy));

        vm.stopBroadcast();
    }

    function readParameters() public view returns (BoltConfig.Parameters memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/parameters.json");
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

        return BoltConfig.Parameters({
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

    function readDeployments() public view returns (BoltConfig.Deployments memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return BoltConfig.Deployments({
            symbioticNetwork: vm.parseJsonAddress(json, ".symbiotic.network"),
            symbioticOperatorRegistry: vm.parseJsonAddress(json, ".symbiotic.operatorRegistry"),
            symbioticOperatorNetOptIn: vm.parseJsonAddress(json, ".symbiotic.networkOptInService"),
            symbioticVaultFactory: vm.parseJsonAddress(json, ".symbiotic.vaultFactory"),
            eigenLayerAVSDirectory: vm.parseJsonAddress(json, ".eigenLayer.avsDirectory"),
            eigenLayerDelegationManager: vm.parseJsonAddress(json, ".eigenLayer.delegationManager"),
            eigenLayerStrategyManager: vm.parseJsonAddress(json, ".eigenLayer.strategyManager")
        });
    }
}
