// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IBoltValidatorsV1} from "../../../src/interfaces/IBoltValidatorsV1.sol";
import {BLS12381} from "../../../src/lib/bls/BLS12381.sol";

import {Script, console} from "forge-std/Script.sol";

/// @notice Script to register Ethereum validators to Bolt
/// @dev this script reads from the config file in /config/holesky/register_validators.json
contract RegisterValidators is Script {
    struct RegisterValidatorsConfig {
        address boltValidators;
        uint128 maxCommittedGasLimit;
        address authorizedOperator;
        BLS12381.G1Point[] pubkeys;
    }

    function run() public {
        address controller = msg.sender;

        console.log("Registering validators to Bolt");
        console.log("Controller address: ", controller);

        RegisterValidatorsConfig memory config = parseConfig();

        vm.startBroadcast(controller);
        IBoltValidatorsV1(config.boltValidators).batchRegisterValidatorsUnsafe(
            config.pubkeys, config.maxCommittedGasLimit, config.authorizedOperator
        );
        vm.stopBroadcast();

        console.log("Validators registered successfully");
    }

    function parseConfig() public view returns (RegisterValidatorsConfig memory config) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/register_validators.json");
        string memory json = vm.readFile(path);

        config.boltValidators = vm.parseJsonAddress(json, ".boltValidators");
        config.authorizedOperator = vm.parseJsonAddress(json, ".authorizedOperator");
        config.maxCommittedGasLimit = uint128(vm.parseJsonUint(json, ".maxCommittedGasLimit"));

        bytes memory pubkeysRaw = vm.parseJson(json, ".pubkeys");
        BLS12381.G1Point[] memory pubkeys = abi.decode(pubkeysRaw, (BLS12381.G1Point[]));
        config.pubkeys = pubkeys;
    }
}
