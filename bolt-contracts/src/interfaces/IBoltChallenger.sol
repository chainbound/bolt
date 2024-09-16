// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

interface IBoltChallenger {
    enum ChallengeStatus {
        Open,
        Won,
        Lost
    }

    struct Challenge {
        uint48 openedAt;
        ChallengeStatus status;
        address challenger;
        address target;
        SignedCommitment commitment;
    }

    struct SignedCommitment {
        uint256 slot;
        bytes signedTx;
        bytes signature;
    }

    struct BlockHeaderData {
        bytes32 stateRoot;
        bytes32 transactionsRoot;
        uint256 blockNumber;
        uint256 timestamp;
        uint256 baseFee;
    }

    struct AccountData {
        uint256 nonce;
        uint256 balance;
    }

    error SlotInTheFuture();
    error BlockIsNotFinalized();
    error InsufficientChallengeBond();
    error ChallengeAlreadyExists();
    error ChallengeAlreadyResolved();
    error ChallengeDoesNotExist();
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
