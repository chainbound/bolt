// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {BLS12381} from "../lib/bls/BLS12381.sol";
import {IBoltValidators} from "./IBoltValidators.sol";

interface IBoltManager {
    error InvalidQuery();
    error AlreadyRegistered();
    error NotRegistered();
    error OperatorNotOptedIn();
    error NotOperator();
    error NotVault();

    function registerSymbioticOperator(address operator) external;

    function pauseSymbioticOperator() external;

    function registerSymbioticVault(address vault) external;

    function pauseSymbioticVault() external;

    function isSymbioticOperatorEnabled(address operator) external view returns (bool);

    function isSymbioticOperatorAuthorizedForValidator(
        address operator,
        bytes32 pubkeyHash
    ) external view returns (bool);

    function getSymbioticOperatorStakeAt(
        address operator,
        address collateral,
        uint48 timestamp
    ) external view returns (uint256);
}
