// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

import {IBoltRegistry} from "../src/interfaces/IBoltRegistry.sol";

contract ReadRegistry is Script {
    address public registryAddress = 0xdF11D829eeC4C192774F3Ec171D822f6Cb4C14d9;

    function run() public view {
        console.log("Bolt registry address:", registryAddress);
        IBoltRegistry registry = IBoltRegistry(registryAddress);

        console.log("Bolt registry minimum collateral:", registry.MINIMUM_COLLATERAL());

        for (uint64 i = 0; i < 2000; i++) {
            try registry.getOperatorForValidator(i) returns (IBoltRegistry.Registrant memory operator) {
                console.log("Operator for validator found", i, ":", operator.operator);
                console.log("Operator RPC:", operator.metadata.rpc);
            } catch {
                // console.log("No operator for validator", i);
            }
        }
    }
}
