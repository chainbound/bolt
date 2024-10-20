// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IBoltValidatorsV1} from "../../../src/interfaces/IBoltValidatorsV1.sol";
import {BLS12381} from "../../../src/lib/bls/BLS12381.sol";

import {Script, console} from "forge-std/Script.sol";

/// @notice Script to register Ethereum validators to Bolt
/// @dev this script reads from the config file in /config/holesky/register_validators.json
contract RegisterValidators is Script {
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

    function _parseConfig() public view returns (RegisterValidatorsConfig memory config) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/holesky/validators.json");
        string memory json = vm.readFile(path);

        config.authorizedOperator = vm.parseJsonAddress(json, ".authorizedOperator");
        config.maxCommittedGasLimit = uint128(vm.parseJsonUint(json, ".maxCommittedGasLimit"));

        bytes[] memory pubkeysRaw = vm.parseJsonBytesArray(json, ".pubkeys");
        BLS12381.G1Point[] memory pubkeys = new BLS12381.G1Point[](pubkeysRaw.length);

        for (uint256 i = 0; i < pubkeysRaw.length; i++) {
            bytes memory pubkey = pubkeysRaw[i];
            require(pubkey.length == 96, "Invalid pubkey length");

            uint256[2] memory x;
            uint256[2] memory y;

            // Assuming each coordinate is split into two 32 bytes
            x[0] = uint256(bytes32(_slice(pubkey, 0, 32)));
            x[1] = uint256(bytes32(_slice(pubkey, 32, 32)));
            y[0] = uint256(bytes32(_slice(pubkey, 64, 32)));
            y[1] = uint256(bytes32(_slice(pubkey, 96, 32)));

            pubkeys[i] = BLS12381.G1Point(x, y);
        }

        config.pubkeys = pubkeys;
    }

    function _slice(bytes memory data, uint256 start, uint256 length) internal pure returns (bytes memory) {
        bytes memory part = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            part[i] = data[i + start];
        }
        return part;
    }
}
