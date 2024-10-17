// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {BoltConfig} from "../../../src/lib/Config.sol";

import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";

/// forge script script/holesky/SymbioticSetup.s.sol --rpc-url $RPC_HOLESKY --private-key $NETWORK_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" registerNetwork
/// forge script script/holesky/SymbioticSetup.s.sol --rpc-url $RPC_HOLESKY --private-key $NETWORK_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" registerMiddleware
contract SymbioticSetup is Script {
    function run(
        string memory arg
    ) public {
        address networkAdmin = msg.sender;
        console.log("Deploying with network admin", networkAdmin);

        vm.startBroadcast();

        if (keccak256(abi.encode(arg)) == keccak256(abi.encode("registerNetwork"))) {
            INetworkRegistry networkRegistry = INetworkRegistry(readNetworkRegistry());

            networkRegistry.registerNetwork();
        } else if (keccak256(abi.encode(arg)) == keccak256(abi.encode("registerMiddleware"))) {
            INetworkMiddlewareService middlewareService = INetworkMiddlewareService(readMiddlewareService());

            address middleware = readMiddleware();

            middlewareService.setMiddleware(middleware);
        }

        vm.stopBroadcast();
    }

    function readNetworkRegistry() public view returns (address) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/network-registry.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonAddress(json, ".networkRegistry");
    }

    function readMiddlewareService() public view returns (address) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/middleware-service.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonAddress(json, ".networkMiddlewareService");
    }

    function readMiddleware() public view returns (address) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/middleware.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonAddress(json, ".networkMiddleware");
    }
}
