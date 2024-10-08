// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IBoltValidators} from "./IBoltValidators.sol";

interface IBoltManager {
    error InvalidQuery();
    error OperatorAlreadyRegistered();
    error OperatorNotRegistered();

    struct Operator {
        string rpc;
        address middleware;
        uint256 timestamp;
    }

    function registerOperator(address operator, string calldata rpc) external;

    function deregisterOperator(
        address operator
    ) external;

    function pauseOperator(
        address operator
    ) external;

    function unpauseOperator(
        address operator
    ) external;

    function isOperator(
        address operator
    ) external view returns (bool);

    function validators() external view returns (IBoltValidators);

    function isOperatorAuthorizedForValidator(address operator, bytes32 pubkeyHash) external view returns (bool);

    function getSupportedRestakingProtocols() external view returns (address[] memory middlewares);
}
