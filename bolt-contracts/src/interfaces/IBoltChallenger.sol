// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IBoltChallenger {
    enum ChallengeStatus {
        // The challenge is open and waiting for a resolution
        Pending,
        // The challenge has been resolved
        Resolved
    }

    enum ChallengeResult {
        // The challenge was successful: the proposer failed to honor the preconfirmation
        Success,
        // The challenge was unsuccessful: the proposer honored the preconfirmation
        Failure
    }

    // Bolt challenge errors
    error ChallengeAlreadyExists();
    error InsufficientBond();
    error Unauthorized();
    error InvalidChallenge();
    error ChallengeNotFound();
    error ChallengeAlreadyResolved();
    error TargetSlotTooFarInThePast();
    error InvalidCommitmentSignature();

    // Relic related errors
    error UnexpectedFactSignature();
    error WrongBlockHeader();

    /// @notice Event emitted when a new challenge is opened
    event NewChallenge(address indexed basedProposer, bytes32 indexed commitmentID, uint256 targetSlot);

    /// @notice Event emitted when a challenge is resolved
    event ChallengeResolved(bytes32 indexed challengeID, ChallengeResult result);
}
