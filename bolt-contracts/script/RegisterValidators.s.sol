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
        string[] memory indexStrings = vm.envString("VALIDATOR_INDEXES", ",");
        string memory rpc = vm.envString("RPC_ADDR");
        vm.startBroadcast(signerKey);

        console.log("Bolt registry address:", registryAddress);
        BoltRegistry registry = BoltRegistry(registryAddress);

        console.log(
            "Bolt registry minimum collateral:",
            registry.MINIMUM_COLLATERAL()
        );

        address sender = vm.addr(signerKey);

        console.log("Sender address:", sender);
        console.log("Sender balance:", sender.balance);

        if (sender.balance < registry.MINIMUM_COLLATERAL()) {
            revert("Insufficient balance");
        }

        for (uint256 i = 0; i < indexStrings.length; i++) {
            validatorIndexes.push(uint64(vm.parseUint(indexStrings[i])));
        }

        // Register with minimal collateral
        registry.register{value: registry.MINIMUM_COLLATERAL()}(
            validatorIndexes,
            rpc,
            ""
        );

        vm.stopBroadcast();
    }
}
