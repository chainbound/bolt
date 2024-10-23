// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {BoltSymbioticMiddlewareV1} from "../../../src/contracts/BoltSymbioticMiddlewareV1.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";

contract RegisterSymbioticOperator is Script {
    struct Config {
        string rpc;
        BoltSymbioticMiddlewareV1 symbioticMiddleware;
        IOptInService symbioticNetworkOptInService;
        address symbioticNetwork;
    }

    function run() public {
        uint256 operatorSk = vm.envUint("OPERATOR_SK");

        address operator = vm.addr(operatorSk);

        Config memory config = _readConfig();

        // First, make sure the operator is opted into the network
        if (!config.symbioticNetworkOptInService.isOptedIn(operator, config.symbioticNetwork)) {
            console.log("Operator is not opted into the network yet. Opting in...");
            vm.startBroadcast(operatorSk);
            config.symbioticNetworkOptInService.optIn(config.symbioticNetwork);
            vm.stopBroadcast();
            console.log("Operator successfully opted into the network");
        }

        console.log("Registering Symbiotic operator");
        console.log("Operator address:", operator);
        console.log("Operator RPC:", config.rpc);

        vm.startBroadcast(operatorSk);
        config.symbioticMiddleware.registerOperator(config.rpc);
        console.log("Successfully registered Symbiotic operator");

        vm.stopBroadcast();
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
}
