// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract BoltRegistry {
    // Struct to hold opted-in proposers as preconfirmers
    struct Preconfirmer {
        // The address of the proposer opted in 
        address addr;
        // The status of the preconfirmer
        PreconfirmerStatus status;
    }

    // Enum to hold the status of the preconfirmer
    enum PreconfirmerStatus {
        Active,
        Inactive
    }

    // Mapping to hold the preconfirmers
    mapping(address => Preconfirmer) public preconfirmers;

    // Error messages
    error PreconfirmerAlreadyExists();
    error PreconfirmerDoesNotExist();
    error Unauthorized();

    // Event to log the status change of a preconfirmer
    event PreconfirmerStatusChanged(address indexed preconfirmer, PreconfirmerStatus status);

    // Modifier to check if the caller is a preconfirmer (no matter its status)
    modifier onlyPreconfirmer() {
        if (preconfirmers[msg.sender].addr == address(0)) {
            revert Unauthorized();
        }
        _;
    }

    /// @notice Constructor
    constructor() {
    }

    /// @notice Add a preconfirmer
    /// @param _preconfirmer The address of the preconfirmer
    function addPreconfirmer(address _preconfirmer) external {
        if (preconfirmers[_preconfirmer].addr != address(0)) {
            revert PreconfirmerAlreadyExists();
        }

        preconfirmers[_preconfirmer] = Preconfirmer(_preconfirmer, PreconfirmerStatus.Active);
        emit PreconfirmerStatusChanged(_preconfirmer, PreconfirmerStatus.Active);
    }

    /// @notice Remove a preconfirmer
    /// @param _preconfirmer The address of the preconfirmer to remove
    function removePreconfirmer(address _preconfirmer) external {
        if (preconfirmers[_preconfirmer].addr == address(0)) {
            revert PreconfirmerDoesNotExist();
        }

        preconfirmers[_preconfirmer].status = PreconfirmerStatus.Inactive;
        emit PreconfirmerStatusChanged(_preconfirmer, PreconfirmerStatus.Inactive);
    }

    /// @notice Check if an address is a preconfirmer
    /// @param _preconfirmer The address to check
    /// @return True if the address is a preconfirmer, false otherwise
    function isPreconfirmer(address _preconfirmer) external view returns (bool) {
        return preconfirmers[_preconfirmer].addr != address(0);
    }

    /// @notice Get the status of a preconfirmer
    /// @param _preconfirmer The address of the preconfirmer
    /// @return The status of the preconfirmer
    function getPreconfirmerStatus(address _preconfirmer) external view returns (PreconfirmerStatus) {
        return preconfirmers[_preconfirmer].status;
    }
}
