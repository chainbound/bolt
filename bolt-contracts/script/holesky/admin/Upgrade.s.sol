// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Upgrades, Options} from "@openzeppelin-foundry-upgrades/src/Upgrades.sol";

import {BoltParametersV1} from "../../../src/contracts/BoltParametersV1.sol";
import {BoltValidatorsV1} from "../../../src/contracts/BoltValidatorsV1.sol";
import {BoltManagerV1} from "../../../src/contracts/BoltManagerV1.sol";
import {BoltEigenLayerMiddlewareV1} from "../../../src/contracts/BoltEigenLayerMiddlewareV1.sol";
import {BoltEigenLayerMiddlewareV2} from "../../../src/contracts/BoltEigenLayerMiddlewareV2.sol";
import {BoltSymbioticMiddlewareV1} from "../../../src/contracts/BoltSymbioticMiddlewareV1.sol";
import {BoltSymbioticMiddlewareV2} from "../../../src/contracts/BoltSymbioticMiddlewareV2.sol";
import {BoltConfig} from "../../../src/lib/Config.sol";

contract UpgradeBolt is Script {
    struct Deployments {
        address boltManager;
        address boltParameters;
        address symbioticNetwork;
        address symbioticOperatorRegistry;
        address symbioticOperatorNetOptIn;
        address symbioticVaultFactory;
        address symbioticMiddleware;
        address[] supportedVaults;
        address eigenLayerAVSDirectory;
        address eigenLayerDelegationManager;
        address eigenLayerStrategyManager;
        address eigenLayerMiddleware;
        address[] supportedStrategies;
    }

    function upgradeSymbioticMiddleware() public {
        address admin = msg.sender;
        console.log("Upgrading Symbiotic middleware with admin", admin);
        // TODO: Validate upgrades with Upgrades.validateUpgrade

        Options memory opts;
        opts.unsafeSkipAllChecks = true;
        opts.referenceContract = "BoltSymbioticMiddlewareV1.sol";

        string memory upgradeTo = "BoltSymbioticMiddlewareV2.sol";

        Deployments memory deployments = _readDeployments();

        bytes memory initSymbioticMiddleware = abi.encodeCall(
            BoltSymbioticMiddlewareV2.initializeV2,
            (
                admin,
                deployments.boltParameters,
                deployments.boltManager,
                deployments.symbioticNetwork,
                deployments.symbioticOperatorRegistry,
                deployments.symbioticOperatorNetOptIn,
                deployments.symbioticVaultFactory
            )
        );

        vm.startBroadcast(admin);

        Upgrades.upgradeProxy(deployments.symbioticMiddleware, upgradeTo, initSymbioticMiddleware, opts);

        vm.stopBroadcast();

        console.log("BoltSymbioticMiddleware proxy upgraded from %s to %s", opts.referenceContract, upgradeTo);

        // TODO: Upgrade contracts with Upgrades.upgradeProxy
    }

    function upgradeEigenLayerMiddleware() public {
        address admin = msg.sender;
        console.log("Upgrading EigenLayer middleware with admin", admin);
        // TODO: Validate upgrades with Upgrades.validateUpgrade

        Options memory opts;
        opts.unsafeSkipAllChecks = true;
        opts.referenceContract = "BoltEigenLayerMiddlewareV1.sol";

        string memory upgradeTo = "BoltEigenLayerMiddlewareV2.sol";

        Deployments memory deployments = _readDeployments();

        bytes memory initEigenLayerMiddleware = abi.encodeCall(
            BoltEigenLayerMiddlewareV2.initializeV2,
            (
                admin,
                deployments.boltParameters,
                deployments.boltManager,
                deployments.eigenLayerAVSDirectory,
                deployments.eigenLayerDelegationManager,
                deployments.eigenLayerStrategyManager
            )
        );

        vm.startBroadcast(admin);

        Upgrades.upgradeProxy(deployments.eigenLayerMiddleware, upgradeTo, initEigenLayerMiddleware, opts);

        vm.stopBroadcast();

        console.log("BoltSymbioticMiddleware proxy upgraded from %s to %s", opts.referenceContract, upgradeTo);
    }

    function _readDeployments() public view returns (Deployments memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return Deployments({
            boltParameters: vm.parseJsonAddress(json, ".bolt.parameters"),
            boltManager: vm.parseJsonAddress(json, ".bolt.manager"),
            symbioticNetwork: vm.parseJsonAddress(json, ".symbiotic.network"),
            symbioticOperatorRegistry: vm.parseJsonAddress(json, ".symbiotic.operatorRegistry"),
            symbioticOperatorNetOptIn: vm.parseJsonAddress(json, ".symbiotic.networkOptInService"),
            symbioticVaultFactory: vm.parseJsonAddress(json, ".symbiotic.vaultFactory"),
            supportedVaults: vm.parseJsonAddressArray(json, ".symbiotic.supportedVaults"),
            symbioticMiddleware: vm.parseJsonAddress(json, ".symbiotic.middleware"),
            eigenLayerAVSDirectory: vm.parseJsonAddress(json, ".eigenLayer.avsDirectory"),
            eigenLayerDelegationManager: vm.parseJsonAddress(json, ".eigenLayer.delegationManager"),
            eigenLayerStrategyManager: vm.parseJsonAddress(json, ".eigenLayer.strategyManager"),
            eigenLayerMiddleware: vm.parseJsonAddress(json, ".eigenLayer.middleware"),
            supportedStrategies: vm.parseJsonAddressArray(json, ".eigenLayer.supportedStrategies")
        });
    }
}
