// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {BoltSymbioticMiddlewareV1} from "../../../src/contracts/BoltSymbioticMiddlewareV1.sol";
import {IBoltManagerV1} from "../../../src/interfaces/IBoltManagerV1.sol";

import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";

contract RegisterSymbioticOperator is Script {
    struct Config {
        string rpc;
        BoltSymbioticMiddlewareV1 symbioticMiddleware;
        IOptInService symbioticNetworkOptInService;
        address symbioticNetwork;
    }

    function S01_registerIntoBolt() public {
        uint256 operatorSk = vm.envUint("OPERATOR_SK");
        string memory rpc = vm.envString("OPERATOR_RPC");

        address operator = vm.addr(operatorSk);

        Config memory config = _readConfig();

        // First, make sure the operator is opted into the network
        require(
            config.symbioticNetworkOptInService.isOptedIn(operator, config.symbioticNetwork),
            "Operator must be opted in into Bolt Network"
        );

        console.log("Registering Symbiotic operator into Bolt");
        console.log("Operator address:", operator);
        console.log("Operator RPC:", rpc);

        vm.startBroadcast(operatorSk);
        config.symbioticMiddleware.registerOperator(rpc);
        console.log("Successfully registered Symbiotic operator");

        vm.stopBroadcast();
    }

    function S02_checkOperatorRegistration() public view {
        address operatorPublicKey = vm.envAddress("OPERATOR_PK");
        console.log("Checking operator registration for address", operatorPublicKey);

        IBoltManagerV1 boltManager = _readBoltManager();
        bool isRegistered = boltManager.isOperator(operatorPublicKey);
        console.log("Operator is registered:", isRegistered);
        require(isRegistered, "Operator is not registered");
    }

    function _readConfig() public view returns (Config memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        string memory operatorPath = string.concat(root, "/config/holesky/operator.json");
        string memory operatorJson = vm.readFile(operatorPath);

        return Config({
            rpc: vm.parseJsonString(operatorJson, ".rpc"),
            symbioticNetwork: vm.parseJsonAddress(json, ".symbiotic.network"),
            symbioticMiddleware: BoltSymbioticMiddlewareV1(vm.parseJsonAddress(json, ".symbiotic.middleware")),
            symbioticNetworkOptInService: IOptInService(vm.parseJsonAddress(json, ".symbiotic.networkOptInService"))
        });
    }

    function _readBoltManager() public view returns (IBoltManagerV1) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);
        return IBoltManagerV1(vm.parseJsonAddress(json, ".bolt.manager"));
    }
}
