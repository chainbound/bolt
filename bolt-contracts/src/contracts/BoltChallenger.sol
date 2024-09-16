// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";

import {SecureMerkleTrie} from "../lib/trie/SecureMerkleTrie.sol";
import {MerkleTrie} from "../lib/trie/MerkleTrie.sol";
import {RLPReader} from "../lib/rlp/RLPReader.sol";
import {BeaconChainUtils} from "../lib/BeaconChainUtils.sol";
import {TransactionDecoder} from "../lib/TransactionDecoder.sol";
import {IBoltChallenger} from "../interfaces/IBoltChallenger.sol";

contract BoltChallenger is IBoltChallenger {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using TransactionDecoder for bytes;
    using TransactionDecoder for TransactionDecoder.Transaction;

    // ========= STORAGE =========

    /// @notice The set of existing unique challenge IDs.
    EnumerableSet.Bytes32Set internal challengeIDs;

    /// @notice The mapping of challenge IDs to their respective challenges.
    mapping(bytes32 => Challenge) internal challenges;

    // ========= CONSTANTS =========

    /// @notice The challenge bond required to open a challenge.
    uint256 public constant CHALLENGE_BOND = 1 ether;

    /// @notice The maximum duration of a challenge to be considered valid.
    uint256 public constant MAX_CHALLENGE_DURATION = 7 days;

    // ========= CONSTRUCTOR =========

    constructor() {}

    // ========= VIEW FUNCTIONS =========

    /// @notice Get all existing challenges.
    /// @dev Should be used in view contexts only to avoid unnecessary gas costs.
    /// @return allChallenges The array of all existing challenges.
    function getAllChallenges() public view returns (Challenge[] memory) {
        Challenge[] memory allChallenges = new Challenge[](challengeIDs.length());

        for (uint256 i = 0; i < challengeIDs.length(); i++) {
            allChallenges[i] = challenges[challengeIDs.at(i)];
        }

        return allChallenges;
    }

    /// @notice Get all currently non-resolved challenges.
    /// @dev Should be used in view contexts only to avoid unnecessary gas costs.
    /// @return openChallenges The array of all currently non-resolved challenges.
    function getOpenChallenges() public view returns (Challenge[] memory) {
        uint256 openCount = 0;
        for (uint256 i = 0; i < challengeIDs.length(); i++) {
            if (challenges[challengeIDs.at(i)].status == ChallengeStatus.Open) {
                openCount++;
            }
        }

        Challenge[] memory openChallenges = new Challenge[](openCount);

        uint256 j = 0;
        for (uint256 i = 0; i < challengeIDs.length(); i++) {
            Challenge memory challenge = challenges[challengeIDs.at(i)];
            if (challenge.status == ChallengeStatus.Open) {
                openChallenges[j] = challenge;
                j++;
            }
        }

        return openChallenges;
    }

    /// @notice Get a challenge by its ID.
    /// @param challengeID The ID of the challenge to get.
    /// @return challenge The challenge with the given ID.
    function getChallengeByID(
        bytes32 challengeID
    ) external view returns (Challenge memory) {
        if (!challengeIDs.contains(challengeID)) {
            revert ChallengeDoesNotExist();
        }

        return challenges[challengeID];
    }

    // ========= CHALLENGE CREATION =========

    // Q: should we add a commit-reveal scheme to prevent frontrunning to steal bonds?
    function openChallenge(
        SignedCommitment calldata commitment
    ) public payable {
        // Check that the challenge bond is sufficient
        if (msg.value < CHALLENGE_BOND) {
            revert InsufficientChallengeBond();
        } else if (msg.value > CHALLENGE_BOND) {
            // Refund the excess value, if any
            payable(msg.sender).transfer(msg.value - CHALLENGE_BOND);
        }

        // Sanity check the slot number
        if (commitment.slot > BeaconChainUtils._getCurrentSlot() - BeaconChainUtils.FINALIZATION_DELAY_SLOTS) {
            // We cannot open challenges for slots that are not finalized yet.
            // This is admittedly a bit strict, since 64-slot deep reorgs are very unlikely.
            revert BlockIsNotFinalized();
        }

        // Reconstruct the commitment digest: `signed tx || slot`
        bytes32 commitmentID = keccak256(abi.encodePacked(commitment.signedTx, commitment.slot));

        // Verify the commitment signature against the digest
        address commitmentSigner = ECDSA.recover(commitmentID, commitment.signature);

        // Check that a challenge for this commitment does not already exist
        if (challengeIDs.contains(commitmentID)) {
            revert ChallengeAlreadyExists();
        }

        // Add the challenge to the set of challenges
        challengeIDs.add(commitmentID);
        challenges[commitmentID] = Challenge({
            openedAt: Time.timestamp(),
            status: ChallengeStatus.Open,
            challenger: msg.sender,
            target: commitmentSigner,
            commitment: commitment
        });

        emit ChallengeOpened(commitmentID, msg.sender, commitmentSigner);
    }

    // ========= CHALLENGE RESOLUTION =========

    function resolveRecentChallenge(
        bytes32 challengeID,
        bytes calldata blockHeaderRLP,
        bytes calldata accountProof
    ) public {
        // Check that the challenge exists
        if (!challengeIDs.contains(challengeID)) {
            revert ChallengeDoesNotExist();
        }

        // The visibility of the BLOCKHASH opcode is limited to the most recent 256 blocks.
        if (challenges[challengeID].commitment.slot < BeaconChainUtils._getCurrentSlot() - 256) {
            revert BlockIsTooOld();
        }

        bytes32 trustedBlockHash = blockhash(challenges[challengeID].commitment.slot);
        _resolveChallenge(challengeID, trustedBlockHash, blockHeaderRLP, accountProof);
    }

    function resolveChallenge(bytes32 challengeID, bytes calldata blockHeaderRLP, bytes calldata accountProof) public {
        // unimplemented!();
    }

    function _resolveChallenge(
        bytes32 challengeID,
        bytes32 trustedBlockHash,
        bytes calldata blockHeaderRLP,
        bytes calldata accountProof
    ) internal {
        // The challenge is assumed to exist at this point, so we can safely access it.
        Challenge storage challenge = challenges[challengeID];

        if (challenge.status != ChallengeStatus.Open) {
            revert ChallengeAlreadyResolved();
        }

        if (challenge.openedAt + MAX_CHALLENGE_DURATION < Time.timestamp()) {
            // If the challenge has expired without being resolved, it is considered lost.
            // TODO: transfer challenge bond back to the challenger
            challenge.status = ChallengeStatus.Lost;
            return;
        }

        // Verify the validity of the header against the trusted block hash
        if (keccak256(blockHeaderRLP) != trustedBlockHash) {
            revert InvalidBlockHash();
        }

        // Decode the block header fields
        BlockHeaderData blockHeader = _decodeBlockHeaderRLP(blockHeaderRLP);

        // Recover the sender of the committed raw signed transaction. It will be the account to prove existence of.
        // For this, we need to reconstruct the transaction preimage and signature from the committed signed transaction.
        TransactionDecoder.Transaction memory decodedTx = challenge.commitment.signedTx.decodeRaw();
        address accountToProve = ECDSA.recover(decodedTx.preimage(), decodedTx.signature());

        // Decode the account fields by checking the account proof against the state root of the block header
        (bool accountExists, bytes memory accountRLP) =
            SecureMerkleTrie.get(abi.encodePacked(accountToProve), accountProof, blockHeader.stateRoot);

        if (!accountExists) {
            revert AccountDoesNotExist();
        }

        AccountData memory account = _decodeAccountRLP(accountRLP);

        if (account.nonce > decodedTx.nonce) {
            // The sender (accountToProve) has sent a transaction with a higher nonce than the committed
            // transaction, before the proposer could include it. Consider the challenge won, as the
            // proposer is not at fault. The bond will be transferred to the proposer.
            // TODO: transfer challenge bond to proposer
            challenge.status = ChallengeStatus.Won;
            return;
        } else if (account.nonce < decodedTx.nonce) {
            // Q: is this a valid case? technically the proposer would be at fault for accepting a commitment of an
            // already included transaction. TBD.
        }

        // Check if the account had enough balance to pay for the worst-case base fee of the committed transaction
        // (i.e., the base fee of the block corresponding to the committed slot number).

        // Verify transaction inclusion proof
        // Note: the transactions trie is built with raw indexes as leaves, without hashing them first.
        // This denotes why we use `MerkleTrie.get` as opposed to `SecureMerkleTrie.get` here.
        (bool txExists, bytes memory transactionRLP) = MerkleTrie.get(txLeaf, txProof, blockHeader.transactionsRoot);

        if (!txExists) {
            revert TransactionNotIncluded();
        }

        // Decode the transactionRLP and check if it matches the committed transaction

        // If all checks pass, the challenge is considered won as the proposer defended with valid proofs.
    }

    // ========= HELPERS =========

    /// @notice Decode the block header fields from an RLP-encoded block header.
    /// @param headerRLP The RLP-encoded block header to decode
    function _decodeBlockHeaderRLP(
        bytes calldata headerRLP
    ) internal pure returns (BlockHeaderData memory blockHeader) {
        RLPReader.RLPItem[] memory headerFields = headerRLP.toRLPItem().readList();

        blockHeader.stateRoot = headerFields[3].readBytes32();
        blockHeader.transactionsRoot = headerFields[4].readBytes32();
        blockHeader.blockNumber = headerFields[8].readUint256();
        blockHeader.timestamp = headerFields[11].readUint256();
        blockHeader.baseFee = headerFields[15].readUint256();
    }

    function _decodeAccountRLP(
        bytes calldata accountRLP
    ) internal pure returns (AccountData memory account) {
        RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();

        account.nonce = accountFields[0].readUint256();
        account.balance = accountFields[1].readUint256();
    }
}
