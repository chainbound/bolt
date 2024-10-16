// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {BoltConfig} from "../src/lib/Config.sol";

contract Utils is Test {
    function readParameters() public view returns (BoltConfig.ParametersConfig memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/config/config.test.json");
        string memory json = vm.readFile(path);

        uint48 epochDuration = uint48(vm.parseJsonUint(json, ".epochDuration"));
        uint48 slashingWindow = uint48(vm.parseJsonUint(json, ".slashingWindow"));
        uint48 maxChallengeDuration = uint48(vm.parseJsonUint(json, ".maxChallengeDuration"));
        bool allowUnsafeRegistration = vm.parseJsonBool(json, ".allowUnsafeRegistration");
        uint256 challengeBond = vm.parseJsonUint(json, ".challengeBond");
        uint256 blockhashEvmLookback = vm.parseJsonUint(json, ".blockhashEvmLookback");
        uint256 justificationDelay = vm.parseJsonUint(json, ".justificationDelay");
        uint256 eth2GenesisTimestamp = vm.parseJsonUint(json, ".eth2GenesisTimestamp");
        uint256 slotTime = vm.parseJsonUint(json, ".slotTime");
        uint256 minimumOperatorStake = vm.parseJsonUint(json, ".minimumOperatorStake");

        return BoltConfig.ParametersConfig({
            epochDuration: epochDuration,
            slashingWindow: slashingWindow,
            maxChallengeDuration: maxChallengeDuration,
            challengeBond: challengeBond,
            blockhashEvmLookback: blockhashEvmLookback,
            justificationDelay: justificationDelay,
            eth2GenesisTimestamp: eth2GenesisTimestamp,
            slotTime: slotTime,
            allowUnsafeRegistration: allowUnsafeRegistration,
            minimumOperatorStake: minimumOperatorStake
        });
    }
}
