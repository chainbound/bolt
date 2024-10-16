// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

interface IBoltChallenger {
    enum ChallengeStatus {
        Open,
        Defended,
        Breached
    }

    struct Challenge {
        bytes32 id;
        uint48 openedAt;
        ChallengeStatus status;
        uint256 targetSlot;
        address challenger;
        address commitmentSigner;
        address commitmentReceiver;
        TransactionData[] committedTxs;
    }

    struct SignedCommitment {
        uint64 slot;
        bytes signature;
        bytes signedTx;
    }

    struct TransactionData {
        bytes32 txHash;
        uint256 nonce;
        uint256 gasLimit;
    }

    struct BlockHeaderData {
        bytes32 parentHash;
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
        // block number where the transactions are included
        uint256 inclusionBlockNumber;
        // RLP-encoded block header of the previous block of the inclusion block
        // (for clarity: `previousBlockHeader.number == inclusionBlockNumber - 1`)
        bytes previousBlockHeaderRLP;
        // RLP-encoded block header where the committed transactions are included
        bytes inclusionBlockHeaderRLP;
        // merkle inclusion proof of the account in the state trie of the previous block
        // (checked against the previousBlockHeader.stateRoot)
        bytes accountMerkleProof;
        // merkle inclusion proof of the transactions in the transaction trie of the inclusion block
        // (checked against the inclusionBlockHeader.txRoot). The order of the proofs should match
        // the order of the committed transactions in the challenge: `Challenge.committedTxs`.
        bytes[] txMerkleProofs;
        // indexes of the committed transactions in the block. The order of the indexes should match
        // the order of the committed transactions in the challenge: `Challenge.committedTxs`.
        uint256[] txIndexesInBlock;
    }

    error SlotInTheFuture();
    error BlockIsNotFinalized();
    error IncorrectChallengeBond();
    error ChallengeAlreadyExists();
    error ChallengeAlreadyResolved();
    error ChallengeDoesNotExist();
    error BlockIsTooOld();
    error InvalidBlockHash();
    error InvalidParentBlockHash();
    error AccountDoesNotExist();
    error TransactionNotIncluded();
    error WrongTransactionHashProof();
    error InvalidBlockNumber();
    error BondTransferFailed();
    error ChallengeNotExpired();
    error ChallengeExpired();
    error EmptyCommitments();
    error UnexpectedMixedSenders();
    error UnexpectedMixedSlots();
    error UnexpectedMixedSigners();
    error UnexpectedNonceOrder();
    error InvalidProofsLength();
    error BeaconRootNotFound();

    event ChallengeOpened(bytes32 indexed challengeId, address indexed challenger, address indexed commitmentSigner);
    event ChallengeDefended(bytes32 indexed challengeId);
    event ChallengeBreached(bytes32 indexed challengeId);

    function getAllChallenges() external view returns (Challenge[] memory);

    function getOpenChallenges() external view returns (Challenge[] memory);

    function getChallengeByID(
        bytes32 challengeID
    ) external view returns (Challenge memory);

    function openChallenge(
        SignedCommitment[] calldata commitments
    ) external payable;

    function resolveExpiredChallenge(
        bytes32 challengeID
    ) external;

    function resolveOpenChallenge(bytes32 challengeID, Proof calldata proof) external;
}
