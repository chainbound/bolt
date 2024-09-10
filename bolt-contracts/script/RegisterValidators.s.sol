// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

import {BoltRegistry} from "../src/contracts/BoltRegistry.sol";

contract RegisterValidators is Script {
    uint256 public signerKey;
    uint64[] public validatorIndexes;
    address public registryAddress = 0xdF11D829eeC4C192774F3Ec171D822f6Cb4C14d9;

    function run() public {
        signerKey = vm.envUint("PRIVATE_KEY");
        string memory rpc = vm.envString("RPC_ADDR");
        vm.startBroadcast(signerKey);

        string memory validatorIndexesEnv = vm.envString("VALIDATOR_INDEXES");
        uint256[] memory indexes = StringToUintArrayLib.fromStr(validatorIndexesEnv);
        for (uint256 i = 0; i < indexes.length; i++) {
            validatorIndexes.push(uint64(indexes[i]));
        }

        console.log("Bolt registry address:", registryAddress);
        BoltRegistry registry = BoltRegistry(registryAddress);

        console.log("Bolt registry minimum collateral:", registry.MINIMUM_COLLATERAL());

        address sender = vm.addr(signerKey);

        console.log("Sender address:", sender);
        console.log("Sender balance:", sender.balance);

        if (sender.balance < registry.MINIMUM_COLLATERAL()) {
            revert("Insufficient balance");
        }

        // Register with minimal collateral
        registry.register{value: registry.MINIMUM_COLLATERAL()}(validatorIndexes, rpc, "");

        vm.stopBroadcast();
    }
}

library StringToUintArrayLib {
    // Maximum number of validators parsed in a single function call
    uint256 constant MAX_VALIDATORS = 256;

    function fromStr(string memory s) internal pure returns (uint256[] memory) {
        bytes memory strBytes = bytes(s);
        uint256[] memory vec = new uint256[](MAX_VALIDATORS); // Initial allocation, will resize later
        uint256 vecIndex = 0;
        uint256 tempNum;
        bool parsingRange = false;
        uint256 rangeStart;

        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == ",") {
                if (parsingRange) {
                    // Handle end of range
                    for (uint256 j = rangeStart; j <= tempNum; j++) {
                        vec[vecIndex] = j;
                        vecIndex++;
                    }
                    parsingRange = false;
                } else {
                    // Handle single number
                    vec[vecIndex] = tempNum;
                    vecIndex++;
                }
                tempNum = 0;
            } else if (strBytes[i] == ".") {
                if (i + 1 < strBytes.length && strBytes[i + 1] == ".") {
                    // Handle start of range
                    parsingRange = true;
                    rangeStart = tempNum;
                    tempNum = 0;
                    i++; // Skip next dot
                }
            } else if (strBytes[i] >= "0" && strBytes[i] <= "9") {
                tempNum = tempNum * 10 + (uint8(strBytes[i]) - 48); // Convert ASCII to integer
            }
        }

        // Handle the last part after the final comma (or single number/range end)
        if (parsingRange) {
            for (uint256 j = rangeStart; j <= tempNum; j++) {
                vec[vecIndex] = j;
                vecIndex++;
            }
        } else {
            vec[vecIndex] = tempNum;
            vecIndex++;
        }

        // Resize array to actual size
        uint256[] memory result = new uint256[](vecIndex);
        for (uint256 i = 0; i < vecIndex; i++) {
            result[i] = vec[i];
        }

        return result;
    }
}
