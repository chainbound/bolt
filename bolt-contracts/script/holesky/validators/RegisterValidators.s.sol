// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IBoltValidatorsV1} from "../interfaces/IBoltValidatorsV1.sol";
import {BLS12381} from "../lib/bls/BLS12381.sol";

import {Script, console} from "forge-std/Script.sol";

/// @notice Script to register Ethereum validators to Bolt
contract RegisterValidators is Script {
    struct RegisterValidatorsConfig {
        address boltValidators;
        uint128 maxCommittedGasLimit;
        address authorizedOperator;
        string[] pubkeys;
    }

    function run(
        string configPath
    ) public {
        address controller = msg.sender;

        console.log("Registering validators to Bolt");
        console.log("Controller address: ", controller);

        RegisterValidatorsConfig memory config = parseConfig(configPath);

        vm.startBroadcast(controller);
        IBoltValidatorsV1(boltValidators).batchRegisterValidatorsUnsafe(
            config.pubkeys, config.maxCommittedGasLimit, config.authorizedOperator
        );
        vm.stopBroadcast();

        console.log("Validators registered successfully");
    }

    function parseConfig(
        string configPath
    ) public view returns (RegisterValidatorsConfig memory config) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/register_validators.json");
        string memory json = vm.readFile(path);

        config.boltValidators = vm.parseJsonAddress(json, "boltValidators");
        config.authorizedOperator = vm.parseJsonAddress(json, "authorizedOperator");
        config.maxCommittedGasLimit = uint128(vm.parseJsonUint(json, "maxCommittedGasLimit"));

        string[] memory pubkeysRaw = vm.parseJsonStringArray(json, "pubkeys");
        BLS12381.G1Point[] memory pubkeys = new BLS12381.G1Point[](pubkeysRaw.length);
        for (uint256 i = 0; i < pubkeysRaw.length; i++) {
            pubkeys[i] = BLS12381.G1Point(vm.parseJsonBytes(json, pubkeysRaw[i]));
        }
        config.pubkeys = pubkeys;
    }
}
