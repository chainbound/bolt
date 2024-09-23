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
    error CollateralNotWhitelisted();

    function getEpochStartTs(
        uint48 epoch
    ) external view returns (uint48);

    function getEpochAtTs(
        uint48 timestamp
    ) external view returns (uint48);

    function getCurrentEpoch() external view returns (uint48);

    function isOperatorAuthorizedForValidator(address operator, bytes32 pubkeyHash) external view returns (bool);
}
