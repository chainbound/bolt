// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IBoltRegistry {
    /// @notice Struct to hold opted-in proposer information
    struct BasedProposer {
        // The address of the proposer opted in
        address addr;
        // The status of the proposer in the protocol
        BoltStatus status;
        // The timestamp of the last time the proposer opted in.
        // This is used to enforce the opt-out cooldown period
        uint256 lastOptedInTimestamp;
    }

    /// @notice Enum to hold the status of the based proposers
    enum BoltStatus {
        Active,
        Inactive
    }

    // Error messages
    error BasedProposerAlreadyExists();
    error BasedProposerDoesNotExist();
    error InvalidStatusChange();
    error CooldownNotElapsed();
    error Unauthorized();
    error NotFound();

    /// @notice Event to log the status change of a based proposer
    event BasedProposerStatusChanged(
        address indexed basedProposer,
        BoltStatus status
    );

    function isActiveBasedProposer(
        address _basedProposer
    ) external view returns (bool);

    function getBasedProposerStatus(
        address _basedProposers
    ) external view returns (BoltStatus);

    function optIn() external;

    function optOut() external;
}
