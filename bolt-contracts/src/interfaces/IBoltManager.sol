// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IBoltValidators} from "./IBoltValidators.sol";

interface IBoltManager {
    error InvalidQuery();

    function validators() external view returns (IBoltValidators);

    function isOperatorAuthorizedForValidator(address operator, bytes32 pubkeyHash) external view returns (bool);

    function getSupportedRestakingProtocols() external view returns (address[] memory middlewares);
}
