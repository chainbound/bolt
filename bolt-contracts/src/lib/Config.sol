// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

library BoltConfig {
    struct Parameters {
        uint48 epochDuration;
        uint48 slashingWindow;
        uint48 maxChallengeDuration;
        uint256 challengeBond;
        uint256 blockhashEvmLookback;
        uint256 justificationDelay;
        uint256 eth2GenesisTimestamp;
        uint256 slotTime;
        bool allowUnsafeRegistration;
        uint256 minimumOperatorStake;
    }

    struct Deployments {
        address symbioticNetwork;
        address symbioticOperatorRegistry;
        address symbioticOperatorNetOptIn;
        address symbioticVaultFactory;
        address[] supportedVaults;
        address eigenLayerAVSDirectory;
        address eigenLayerDelegationManager;
        address eigenLayerStrategyManager;
        address[] supportedStrategies;
    }

    struct SymbioticDeployments {
        address symbioticNetworkRegistry;
        address symbioticNetworkMiddlewareService;
    }
}
