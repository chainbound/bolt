// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";

/// forge script script/holesky/Symbiotic.s.sol --rpc-url $RPC_HOLESKY --private-key $NETWORK_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" registerNetwork
/// forge script script/holesky/Symbiotic.s.sol --rpc-url $RPC_HOLESKY --private-key $NETWORK_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" registerMiddleware
contract SymbioticHelper is Script {
    function run(
        string memory arg
    ) public {
        address networkAdmin = msg.sender;
        console.log("Running with network admin", networkAdmin);

        vm.startBroadcast(networkAdmin);

        if (keccak256(abi.encode(arg)) == keccak256(abi.encode("registerNetwork"))) {
            INetworkRegistry networkRegistry = INetworkRegistry(readNetworkRegistry());

            console.log("Registering network with NetworkRegistry (%s)", address(networkRegistry));

            networkRegistry.registerNetwork();
        } else if (keccak256(abi.encode(arg)) == keccak256(abi.encode("registerMiddleware"))) {
            INetworkMiddlewareService middlewareService = INetworkMiddlewareService(readMiddlewareService());

            address middleware = readMiddleware();

            console.log(
                "Registering network middleware (%s) with MiddlewareService (%s)",
                middleware,
                address(middlewareService)
            );

            middlewareService.setMiddleware(middleware);
        }

        vm.stopBroadcast();
    }

    function readNetworkRegistry() public view returns (address) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonAddress(json, ".symbiotic.networkRegistry");
    }

    function readMiddlewareService() public view returns (address) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonAddress(json, ".symbiotic.networkMiddlewareService");
    }

    function readMiddleware() public view returns (address) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonAddress(json, ".symbiotic.middleware");
    }
}
