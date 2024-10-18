// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Upgrades, Options} from "@openzeppelin-foundry-upgrades/src/Upgrades.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IStrategy} from "@eigenlayer/src/contracts/interfaces/IStrategy.sol";

import {BoltParametersV1} from "../../../src/contracts/BoltParametersV1.sol";
import {BoltValidatorsV1} from "../../../src/contracts/BoltValidatorsV1.sol";
import {BoltManagerV1} from "../../../src/contracts/BoltManagerV1.sol";
import {BoltEigenLayerMiddlewareV1} from "../../../src/contracts/BoltEigenLayerMiddlewareV1.sol";
import {BoltSymbioticMiddlewareV1} from "../../../src/contracts/BoltSymbioticMiddlewareV1.sol";
import {BoltConfig} from "../../../src/lib/Config.sol";

/// @notice Script to deploy the Bolt contracts.
contract DeployBolt is Script {
    function run() public {
        // The admin address will be authorized to call the adminOnly functions
        // on the contract implementations, as well as upgrade the contracts.
        address admin = msg.sender;
        console.log("Deploying with admin", admin);

        BoltConfig.Parameters memory config = readParameters();
        BoltConfig.Deployments memory deployments = readDeployments();

        vm.startBroadcast(admin);

        // TODO: Fix safe deploy, currently failing with `ASTDereferencerError` from openzeppelin
        Options memory opts;
        opts.unsafeSkipAllChecks = true;

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
        address parametersProxy = Upgrades.deployUUPSProxy("BoltParametersV1.sol", initParameters, opts);
        console.log("BoltParametersV1 proxy deployed at", parametersProxy);

        // Generate the `initialize` call data for the contract.
        bytes memory initValidators = abi.encodeCall(BoltValidatorsV1.initialize, (admin, parametersProxy));
        // Deploy the UUPSProxy through the `Upgrades` library, with the correct `initialize` call data.
        address validatorsProxy = Upgrades.deployUUPSProxy("BoltValidatorsV1.sol", initValidators, opts);
        console.log("BoltValidatorsV1 proxy deployed at", validatorsProxy);

        bytes memory initManager = abi.encodeCall(BoltManagerV1.initialize, (admin, parametersProxy, validatorsProxy));
        address managerProxy = Upgrades.deployUUPSProxy("BoltManagerV1.sol", initManager, opts);
        console.log("BoltManagerV1 proxy deployed at", managerProxy);

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
            Upgrades.deployUUPSProxy("BoltEigenLayerMiddlewareV1.sol", initEigenLayerMiddleware, opts);
        console.log("BoltEigenLayerMiddlewareV1 proxy deployed at", eigenLayerMiddlewareProxy);

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
            Upgrades.deployUUPSProxy("BoltSymbioticMiddlewareV1.sol", initSymbioticMiddleware, opts);
        console.log("BoltSymbioticMiddlewareV1 proxy deployed at", address(symbioticMiddlewareProxy));

        console.log("Core contracts deployed succesfully, whitelisting middleware contracts in BoltManager...");
        console.log("EigenLayer middleware:", address(eigenLayerMiddlewareProxy));
        console.log("Symbiotic middleware:", address(symbioticMiddlewareProxy));
        BoltManagerV1(managerProxy).addRestakingProtocol(address(eigenLayerMiddlewareProxy));
        BoltManagerV1(managerProxy).addRestakingProtocol(address(symbioticMiddlewareProxy));

        console.log("Whitelisted middleware contracts in BoltManager");
        console.log("Registering supported Symbiotic Vaults...");

        for (uint256 i = 0; i < deployments.supportedVaults.length; i++) {
            IVault vault = IVault(deployments.supportedVaults[i]);
            console.log("Registering vault with collateral: %s (address: %s)", vault.collateral(), address(vault));
            BoltSymbioticMiddlewareV1(symbioticMiddlewareProxy).registerVault(address(deployments.supportedVaults[i]));
        }

        console.log("Registering supported EigenLayer Strategies...");

        for (uint256 i = 0; i < deployments.supportedStrategies.length; i++) {
            IStrategy strategy = IStrategy(deployments.supportedStrategies[i]);
            console.log(
                "Registering strategy with collateral: %s (address: %s)",
                address(strategy.underlyingToken()),
                address(strategy)
            );
            BoltEigenLayerMiddlewareV1(eigenLayerMiddlewareProxy).registerStrategy(address(strategy));
        }

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
            supportedVaults: vm.parseJsonAddressArray(json, ".symbiotic.supportedVaults"),
            eigenLayerAVSDirectory: vm.parseJsonAddress(json, ".eigenLayer.avsDirectory"),
            eigenLayerDelegationManager: vm.parseJsonAddress(json, ".eigenLayer.delegationManager"),
            eigenLayerStrategyManager: vm.parseJsonAddress(json, ".eigenLayer.strategyManager"),
            supportedStrategies: vm.parseJsonAddressArray(json, ".eigenLayer.supportedStrategies")
        });
    }
}
