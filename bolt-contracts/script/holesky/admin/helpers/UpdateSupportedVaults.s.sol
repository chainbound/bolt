// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";

import {BoltSymbioticMiddlewareV1} from "../../../../src/contracts/BoltSymbioticMiddlewareV1.sol";

contract UpdateSupportedVaults is Script {
    function run() public {
        BoltSymbioticMiddlewareV1 middleware = _readSymbioticMiddleware();

        address[] memory whitelisted = middleware.getWhitelistedVaults();
        address[] memory toWhitelist = _readVaultsToWhitelist();

        vm.startBroadcast();

        // Step 1: Whitelist new vaults
        for (uint256 i = 0; i < toWhitelist.length; i++) {
            address vault = toWhitelist[i];

            bool isWhitelisted = false;
            for (uint256 j = 0; j < whitelisted.length; j++) {
                if (whitelisted[j] == vault) {
                    isWhitelisted = true;
                    break;
                }
            }

            if (!isWhitelisted) {
                console.log("Whitelisting vault", vault);
                middleware.registerVault(vault);
            }
        }

        // Step 2: Remove vaults from contract that are not in the supported vaults list
        for (uint256 i = 0; i < whitelisted.length; i++) {
            address vault = whitelisted[i];

            bool isSupported = false;
            for (uint256 j = 0; j < toWhitelist.length; j++) {
                if (toWhitelist[j] == vault) {
                    isSupported = true;
                    break;
                }
            }

            if (!isSupported) {
                console.log("Removing vault", vault);
                middleware.deregisterVault(vault);
            }
        }

        vm.stopBroadcast();
    }

    function _readVaultsToWhitelist() public view returns (address[] memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonAddressArray(json, ".symbiotic.supportedVaults");
    }

    function _readSymbioticMiddleware() public view returns (BoltSymbioticMiddlewareV1) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return BoltSymbioticMiddlewareV1(vm.parseJsonAddress(json, ".symbiotic.middleware"));
    }
}
