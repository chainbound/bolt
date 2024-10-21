// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IBoltValidatorsV1} from "../../../src/interfaces/IBoltValidatorsV1.sol";
import {BLS12381} from "../../../src/lib/bls/BLS12381.sol";

import {Script, console} from "forge-std/Script.sol";

/// @notice Script to register Ethereum validators to Bolt
/// @dev this script reads from the config file in /config/holesky/register_validators.json
contract RegisterValidators is Script {
    using BLS12381 for BLS12381.G1Point;

    struct RegisterValidatorsConfig {
        uint128 maxCommittedGasLimit;
        address authorizedOperator;
        BLS12381.G1Point[] pubkeys;
    }

    function run() public {
        address controller = msg.sender;

        console.log("Registering validators to Bolt");
        console.log("Controller address: ", controller);

        IBoltValidatorsV1 validators = _readValidators();
        RegisterValidatorsConfig memory config = _parseConfig();

        vm.startBroadcast(controller);
        validators.batchRegisterValidatorsUnsafe(config.pubkeys, config.maxCommittedGasLimit, config.authorizedOperator);
        vm.stopBroadcast();

        console.log("Validators registered successfully");
    }

    function _readValidators() public view returns (IBoltValidatorsV1) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/deployments.json");
        string memory json = vm.readFile(path);

        return IBoltValidatorsV1(vm.parseJsonAddress(json, ".bolt.validators"));
    }

    function _parseConfig() public returns (RegisterValidatorsConfig memory config) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/validators.json");
        string memory json = vm.readFile(path);

        config.authorizedOperator = vm.parseJsonAddress(json, ".authorizedOperator");
        config.maxCommittedGasLimit = uint128(vm.parseJsonUint(json, ".maxCommittedGasLimit"));

        string[] memory pubkeysRaw = vm.parseJsonStringArray(json, ".pubkeys");
        BLS12381.G1Point[] memory pubkeys = new BLS12381.G1Point[](pubkeysRaw.length);

        for (uint256 i = 0; i < pubkeysRaw.length; i++) {
            string memory pubkey = pubkeysRaw[i];

            string[] memory convertCmd = new string[](2);
            convertCmd[0] = "./script/pubkey_to_g1_wrapper.sh";
            convertCmd[1] = pubkey;

            bytes memory output = vm.ffi(convertCmd);
            string memory outputStr = string(output);
            string[] memory array = vm.split(outputStr, ",");

            uint256[2] memory x = _bytesToParts(vm.parseBytes(array[0]));
            uint256[2] memory y = _bytesToParts(vm.parseBytes(array[1]));

            console.logBytes(abi.encodePacked(x));
            console.logBytes(abi.encodePacked(y));

            pubkeys[i] = BLS12381.G1Point(x, y);

            console.log("Registering pubkey:", vm.toString(abi.encodePacked(pubkeys[i].compress())));
        }

        config.pubkeys = pubkeys;
    }

    function _bytesToParts(
        bytes memory data
    ) public pure returns (uint256[2] memory out) {
        require(data.length == 48, "Invalid data length");

        uint256 value1;
        uint256 value2;

        // Load the first 32 bytes into value1
        assembly {
            value1 := mload(add(data, 32))
        }
        value1 = value1 >> 128; // Clear unwanted upper bits

        // Load the next 16 bytes into value2
        assembly {
            value2 := mload(add(data, 48))
        }
        // value2 = value2 >> 128;

        out[0] = value1;
        out[1] = value2;
    }
}
