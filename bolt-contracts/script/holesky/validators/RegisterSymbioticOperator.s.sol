// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {BoltSymbioticMiddlewareV1} from "../../../src/contracts/BoltSymbioticMiddlewareV1.sol";

contract RegisterSymbioticOperator is Script {
    function run() public {
        uint256 operatorSk = vm.envUint("OPERATOR_SK");

        address operator = vm.addr(operatorSk);

        BoltSymbioticMiddlewareV1 middleware = _readMiddleware();
        string memory rpc = _readRPC();

        console.log("Registering Symbiotic operator");
        console.log("Operator address:", operator);
        console.log("Operator RPC:", rpc);

        vm.startBroadcast(operatorSk);
        middleware.registerOperator(rpc);
        console.log("Successfully registered Symbiotic operator");

        vm.stopBroadcast();
    }

    function _readMiddleware() public view returns (BoltSymbioticMiddlewareV1) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return BoltSymbioticMiddlewareV1(vm.parseJsonAddress(json, ".symbiotic.middleware"));
    }

    function _readRPC() public view returns (string memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/operator.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonString(json, ".rpc");
    }
}
