// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {BoltEigenLayerMiddlewareV1} from "../../../src/contracts/BoltEigenLayerMiddlewareV1.sol";

contract RegisterAVS is Script {
    function run() public {
        address admin = msg.sender;
        console.log("Running with admin address:", admin);

        BoltEigenLayerMiddlewareV1 middleware = BoltEigenLayerMiddlewareV1(readMiddleware());

        string memory avsURI = "https://boltprotocol.xyz/avs.json";
        console.log("Setting AVS metadata URI to:", avsURI);

        vm.startBroadcast(admin);

        middleware.updateAVSMetadataURI(avsURI);
        vm.stopBroadcast();
    }

    function readMiddleware() public view returns (address) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return vm.parseJsonAddress(json, ".eigenLayer.networkMiddleware");
    }
}
