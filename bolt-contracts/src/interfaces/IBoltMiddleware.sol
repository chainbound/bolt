// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {BLS12381} from "../lib/bls/BLS12381.sol";
import {IBoltValidators} from "./IBoltValidators.sol";
import {IBoltManager} from "./IBoltManager.sol";

interface IBoltMiddleware {
    error InvalidQuery();
    error AlreadyRegistered();
    error NotRegistered();
    error OperatorNotOptedIn();
    error NotOperator();
    error CollateralNotWhitelisted();
    error NotAllowed();

    function nameHash() external view returns (bytes32);

    function getEpochStartTs(
        uint48 epoch
    ) external view returns (uint48);

    function getEpochAtTs(
        uint48 timestamp
    ) external view returns (uint48);

    function getCurrentEpoch() external view returns (uint48);

    function addWhitelistedCollateral(
        address collateral
    ) external;

    function removeWhitelistedCollateral(
        address collateral
    ) external;

    function getWhitelistedCollaterals() external view returns (address[] memory);

    function isCollateralWhitelisted(
        address collateral
    ) external view returns (bool);

    function registerOperator(
        address operator
    ) external;

    function pauseOperator() external;

    function unpauseOperator() external;

    function isOperatorEnabled(
        address operator
    ) external view returns (bool);

    function getProposersStatus(
        bytes32[] memory pubkeyHashes
    ) external view returns (IBoltManager.ProposerStatus[] memory);

    function getProposerStatus(
        bytes32 pubkeyHash
    ) external view returns (IBoltManager.ProposerStatus memory);

    function isOperatorAuthorizedForValidator(address operator, bytes32 pubkeyHash) external view returns (bool);

    function getOperatorStake(address operator, address collateral) external view returns (uint256);

    function getOperatorStakeAt(
        address operator,
        address collateral,
        uint48 timestamp
    ) external view returns (uint256);

    function getTotalStake(uint48 epoch, address collateral) external view returns (uint256);
}
