// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";

contract DeployValidatorsRegistry is Script {
    uint256 public signerKey;

    function run() public {
        signerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(signerKey);

        BoltValidators validators = new BoltValidators();
        console.log("BoltValidators deployed at", address(validators));

        vm.stopBroadcast();
    }
}
