// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract BoltRegistry {
    uint256 public constant OPT_OUT_COOLDOWN = 1 days;

    // Struct to hold opted-in proposers
    struct BasedProposer {
        // The address of the proposer opted in
        address addr;
        // The status of the proposer in the protocol
        BoltStatus status;
        // The timestamp of the last time the proposer opted in.
        // This is used to enforce the opt-out cooldown period
        uint256 lastOptedInTimestamp;
    }

    // Enum to hold the status of the based proposers
    enum BoltStatus {
        Active,
        Inactive
    }

    // Mapping to hold the based proposers
    mapping(address => BasedProposer) public basedProposers;

    // Error messages
    error BasedProposerAlreadyExists();
    error BasedProposerDoesNotExist();
    error InvalidStatusChange();
    error CooldownNotElapsed();
    error Unauthorized();
    error NotFound();

    // Event to log the status change of a based proposer
    event BasedProposerStatusChanged(address indexed basedProposer, BoltStatus status);

    /// @notice Constructor
    constructor() {}

    /// @notice Allows a based proposer to opt-in to the protocol
    function optIn() external {
        if (basedProposers[msg.sender].addr != address(0)) {
            revert BasedProposerAlreadyExists();
        }

        basedProposers[msg.sender] = BasedProposer(msg.sender, BoltStatus.Active, block.timestamp);
        emit BasedProposerStatusChanged(msg.sender, BoltStatus.Active);
    }

    /// @notice Allows a based proposer to opt-out of the protocol
    function optOut() external {
        BasedProposer memory basedProposer = basedProposers[msg.sender];

        if (basedProposer.addr != msg.sender) {
            revert BasedProposerDoesNotExist();
        }
        if (basedProposer.status == BoltStatus.Inactive) {
            revert InvalidStatusChange();
        }
        if (block.timestamp - basedProposer.lastOptedInTimestamp < OPT_OUT_COOLDOWN) {
            revert CooldownNotElapsed();
        }

        basedProposer.status = BoltStatus.Inactive;
        emit BasedProposerStatusChanged(msg.sender, BoltStatus.Inactive);
    }

    /// @notice Check if an address is a based proposer
    /// @param _basedProposer The address to check
    /// @return True if the address is a based proposer, false otherwise
    function isBasedProposer(address _basedProposer) external view returns (bool) {
        return basedProposers[_basedProposer].addr != address(0);
    }

    /// @notice Get the status of a based proposer
    /// @param _basedProposers The address of the based proposer
    /// @return The status of the based proposer
    function getBasedProposerStatus(address _basedProposers) external view returns (BoltStatus) {
        if (basedProposers[_basedProposers].addr == address(0)) {
            revert BasedProposerDoesNotExist();
        }

        return basedProposers[_basedProposers].status;
    }
}
