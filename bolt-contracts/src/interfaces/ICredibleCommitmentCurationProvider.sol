// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

interface ICredibleCommitmentCurationProvider {

    /// @notice Method check for approval for provided registration root against
    /// internal CredibleCommitmentCurationProvider logic.
    function isRegistrationRootApproved(bytes32 registrationRoot) external view returns (bool);

    /// @notice Hooke used to revert if provided registration root is not approved.
    function hookOnlyApprovedRegistrationRoot(bytes32 registrationRoot) external view;
}
