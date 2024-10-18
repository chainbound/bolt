// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {IAVSDirectory} from "@eigenlayer/src/contracts/interfaces/IAVSDirectory.sol";
import {ISignatureUtils} from "@eigenlayer/src/contracts/interfaces/ISignatureUtils.sol";

import {BoltEigenLayerMiddlewareV1} from "../../../src/contracts/BoltEigenLayerMiddlewareV1.sol";

contract RegisterEigenLayerOperator is Script {
    struct OperatorConfig {
        string rpc;
        bytes32 salt;
        uint256 expiry;
    }

    function run() public {
        uint256 operatorSk = vm.envUint("OPERATOR_SK");

        address operator = vm.addr(operatorSk);

        BoltEigenLayerMiddlewareV1 middleware = _readMiddleware();
        IAVSDirectory avsDirectory = _readAvsDirectory();
        OperatorConfig memory config = _readConfig("config/holesky/operator.json");

        console.log("Registering EigenLayer operator");
        console.log("Operator address:", operator);

        vm.startBroadcast(operatorSk);

        bytes32 digest = avsDirectory.calculateOperatorAVSRegistrationDigestHash({
            operator: operator,
            avs: address(middleware),
            salt: config.salt,
            expiry: config.expiry
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorSk, digest);
        bytes memory rawSignature = abi.encodePacked(r, s, v);

        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature =
            ISignatureUtils.SignatureWithSaltAndExpiry(rawSignature, config.salt, config.expiry);

        middleware.registerOperator(config.rpc, operatorSignature);

        vm.stopBroadcast();
    }

    function _readMiddleware() public view returns (BoltEigenLayerMiddlewareV1) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return BoltEigenLayerMiddlewareV1(vm.parseJsonAddress(json, ".eigenLayer.networkMiddleware"));
    }

    function _readAvsDirectory() public view returns (IAVSDirectory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return IAVSDirectory(vm.parseJsonAddress(json, ".eigenLayer.avsDirectory"));
    }

    function _readConfig(
        string memory path
    ) public view returns (OperatorConfig memory) {
        string memory json = vm.readFile(path);

        bytes32 salt = bytes32(0);
        uint256 expiry = UINT256_MAX;

        try vm.parseJsonBytes32(json, ".salt") returns (bytes32 val) {
            salt = val;
        } catch {
            console.log("No salt found in config, using 0");
        }

        try vm.parseJsonUint(json, ".expiry") returns (uint256 val) {
            expiry = val;
        } catch {
            console.log("No expiry found in config, using UINT256_MAX");
        }

        return OperatorConfig({rpc: vm.parseJsonString(json, ".rpc"), salt: salt, expiry: expiry});
    }
}
