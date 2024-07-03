// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IBoltRegistry {
    /// @notice Struct to hold opted-in proposer information
    struct Registrant {
        // The address of the operator
        address operator;
        // The validator indexes this registrant is responsible for
        uint64[] validatorIndexes;
        uint256 enteredAt;
        uint256 exitInitiatedAt;
        uint256 balance;
        Status status;
        MetaData metadata;
    }

    struct MetaData {
        string rpc;
        bytes extra;
    }

    /// @notice Enum to hold the status of the based proposers
    enum Status {
        // Default INACTIVE
        INACTIVE,
        ACTIVE,
        FROZEN,
        EXITING
    }

    // Error messages
    error AlreadyOptedIn();
    error InsufficientCollateral();
    error BasedProposerDoesNotExist();
    error InvalidStatusChange();
    error CooldownNotElapsed();
    error Unauthorized();
    error NotFound();

    /// @notice Event to log the status change of a based proposer
    event StatusChange(address indexed operator, Status status);

    event Registered(
        address indexed operator,
        uint64[] validatorIndexes,
        MetaData metadata
    );

    function register(
        uint64[] calldata validatorIndexes,
        string calldata rpc,
        bytes calldata extra
    ) external payable;

    function isActiveOperator(address _operator) external view returns (bool);

    function getOperatorStatus(
        address _operator
    ) external view returns (Status);

    function getOperatorForValidator(
        uint64 _validatorIndex
    ) external view returns (Registrant memory);

    function startExit() external;

    function confirmExit(address payable recipient) external;
}
