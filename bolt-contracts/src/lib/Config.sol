// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

library BoltConfig {
    struct ParametersConfig {
        uint48 epochDuration;
        uint48 slashingWindow;
        uint48 maxChallengeDuration;
        uint256 challengeBond;
        uint256 blockhashEvmLookback;
        uint256 justificationDelay;
        uint256 eth2GenesisTimestamp;
        uint256 slotTime;
        bool allowUnsafeRegistration;
    }
}
