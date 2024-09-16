// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

interface IBoltChallenger {
    struct Challenge {
        uint48 openedAt;
        bool resolved;
        address challenger;
        address target;
        SignedCommitment commitment;
    }

    struct SignedCommitment {
        uint256 slot;
        bytes signedTx;
        bytes signature;
    }

    error SlotInTheFuture();
    error BlockIsNotFinalized();
    error InsufficientChallengeBond();
    error ChallengeAlreadyExists();
    error BlockIsTooOld();
    error InvalidBlockHash();
    error AccountDoesNotExist();

    event ChallengeOpened(bytes32 indexed challengeId, address indexed challenger, address indexed target);

    function openChallenge(
        SignedCommitment calldata commitment
    ) external payable;

    function resolveChallenge(
        uint256 challengeId
    ) external;
}
