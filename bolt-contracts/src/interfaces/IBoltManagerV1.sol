// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IBoltValidatorsV1} from "./IBoltValidatorsV1.sol";

interface IBoltManagerV1 {
    error InvalidQuery();
    error OperatorAlreadyRegistered();
    error OperatorNotRegistered();
    error UnauthorizedMiddleware();
    error InactiveOperator();

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

    function validators() external view returns (IBoltValidatorsV1);

    function getProposerStatus(
        bytes32 pubkeyHash
    ) external view returns (IBoltValidatorsV1.ProposerStatus memory status);

    function getProposerStatuses(
        bytes32[] calldata pubkeyHashes
    ) external view returns (IBoltValidatorsV1.ProposerStatus[] memory statuses);

    function isOperatorAuthorizedForValidator(address operator, bytes32 pubkeyHash) external view returns (bool);

    function getSupportedRestakingProtocols() external view returns (address[] memory middlewares);
}
