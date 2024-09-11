// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {BLS12381} from "../lib/bls/BLS12381.sol";
import {IBoltValidators} from "./IBoltValidators.sol";

interface IBoltManager {
    struct ProposerStatus {
        bytes32 pubkeyHash;
        bool active;
        address operator;
        address[] collaterals;
        uint256[] amounts;
    }

    error InvalidQuery();
    error AlreadyRegistered();
    error NotRegistered();
    error OperatorNotOptedIn();
    error NotOperator();
    error NotVault();
    error CollateralNotWhitelisted();
    error UnknownSlasherType();
    error SlashAmountTooHigh();
    error StrategyNotAllowed();
    error OperatorNotRegisteredToAVS();

    function getEpochStartTs(uint48 epoch) external view returns (uint48);

    function getEpochAtTs(uint48 timestamp) external view returns (uint48);

    function getCurrentEpoch() external view returns (uint48);

    function addWhitelistedSymbioticCollateral(address collateral) external;

    function removeWhitelistedSymbioticCollateral(address collateral) external;

    function getWhitelistedSymbioticCollaterals()
        external
        view
        returns (address[] memory);

    function isSymbioticCollateralWhitelisted(
        address collateral
    ) external view returns (bool);

    function registerSymbioticOperator(address operator) external;

    function pauseSymbioticOperator() external;

    function unpauseSymbioticOperator() external;

    function registerSymbioticVault(address vault) external;

    function pauseSymbioticVault() external;

    function unpauseSymbioticVault() external;

    function isSymbioticVaultEnabled(
        address vault
    ) external view returns (bool);

    function isSymbioticOperatorEnabled(
        address operator
    ) external view returns (bool);

    function getSymbioticProposerStatus(
        bytes32[] memory pubkeyHashes
    ) external view returns (ProposerStatus[] memory);

    function getSymbioticProposerStatus(
        bytes32 pubkeyHash
    ) external view returns (ProposerStatus memory);

    function isOperatorAuthorizedForValidator(
        address operator,
        bytes32 pubkeyHash
    ) external view returns (bool);

    function getSymbioticOperatorStake(
        address operator,
        address collateral
    ) external view returns (uint256);

    function getSymbioticOperatorStakeAt(
        address operator,
        address collateral,
        uint48 timestamp
    ) external view returns (uint256);

    function getSymbioticTotalStake(
        uint48 epoch,
        address collateral
    ) external view returns (uint256);
}
