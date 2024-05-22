// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IBoltRegistry} from "../interfaces/IBoltRegistry.sol";

contract BoltRegistry is IBoltRegistry {
    uint256 public constant OPT_OUT_COOLDOWN = 1 days;

    // Mapping to hold the based proposers
    mapping(address => BasedProposer) public basedProposers;

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

    /// @notice Check if an address is a based proposer opted into the protocol
    /// @param _basedProposer The address to check
    /// @return True if the address is an active based proposer, false otherwise
    function isActiveBasedProposer(address _basedProposer) external view returns (bool) {
        if (basedProposers[_basedProposer].addr == address(0)) return false;
        return basedProposers[_basedProposer].status == BoltStatus.Active;
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
