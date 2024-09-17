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
        uint64 slot;
        bytes signature;
        bytes signedTx;
    }

    struct BlockHeaderData {
        bytes32 stateRoot;
        bytes32 txRoot;
        uint256 blockNumber;
        uint256 timestamp;
        uint256 baseFee;
    }

    struct AccountData {
        uint256 nonce;
        uint256 balance;
    }

    struct Proof {
        bytes blockHeaderRLP;
        bytes accountMerkleProof;
        bytes txMerkleProof;
        uint256 blockNumber;
        uint256 txIndexInBlock;
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
    error TransactionNotIncluded();
    error WrongTransactionHashProof();
    error InvalidBlockNumber();

    event ChallengeOpened(bytes32 indexed challengeId, address indexed challenger, address indexed target);

    function getAllChallenges() external view returns (Challenge[] memory);

    function getOpenChallenges() external view returns (Challenge[] memory);

    function getChallengeByID(
        bytes32 challengeID
    ) external view returns (Challenge memory);

    function openChallenge(
        SignedCommitment calldata commitment
    ) external payable;

    function resolveRecentChallenge(bytes32 challengeID, Proof calldata proof) external;

    function resolveChallenge(bytes32 challengeID, Proof calldata proof) external;
}
