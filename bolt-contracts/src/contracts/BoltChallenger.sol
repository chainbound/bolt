// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";

import {SecureMerkleTrie} from "../lib/trie/SecureMerkleTrie.sol";
import {MerkleTrie} from "../lib/trie/MerkleTrie.sol";
import {RLPReader} from "../lib/rlp/RLPReader.sol";
import {RLPWriter} from "../lib/rlp/RLPWriter.sol";
import {BeaconChainUtils} from "../lib/BeaconChainUtils.sol";
import {TransactionDecoder} from "../lib/TransactionDecoder.sol";
import {IBoltChallenger} from "../interfaces/IBoltChallenger.sol";

contract BoltChallenger is IBoltChallenger {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using TransactionDecoder for bytes;
    using TransactionDecoder for TransactionDecoder.Transaction;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // ========= STORAGE =========

    /// @notice The set of existing unique challenge IDs.
    EnumerableSet.Bytes32Set internal challengeIDs;

    /// @notice The mapping of challenge IDs to their respective challenges.
    mapping(bytes32 => Challenge) internal challenges;

    // ========= CONSTANTS =========

    /// @notice The challenge bond required to open a challenge.
    uint256 public constant COMMITMENT_BOND = 1 ether;

    /// @notice The maximum duration of a challenge to be considered valid.
    uint256 public constant MAX_CHALLENGE_DURATION = 7 days;

    /// @notice The maximum number of blocks to look back for block hashes in the EVM.
    uint256 public constant BLOCKHASH_EVM_LOOKBACK = 256;

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
    ) public view returns (Challenge memory) {
        if (!challengeIDs.contains(challengeID)) {
            revert ChallengeDoesNotExist();
        }

        return challenges[challengeID];
    }

    // ========= CHALLENGE CREATION =========

    /// @notice Open a challenge against a bundle of committed transactions.
    /// @dev The challenge bond must be paid in order to open a challenge.
    /// @param commitments The signed commitments to open a challenge for.
    function openChallenge(
        SignedCommitment[] calldata commitments
    ) public payable {
        if (commitments.length == 0) {
            revert EmptyCommitments();
        }

        // Check that the challenge bond is sufficient
        uint256 expectedBond = COMMITMENT_BOND * commitments.length;
        if (msg.value < expectedBond) {
            revert InsufficientChallengeBond();
        } else if (msg.value > expectedBond) {
            // Refund the excess value, if any
            payable(msg.sender).transfer(msg.value - expectedBond);
        }

        uint256 targetSlot = commitments[0].slot;
        if (targetSlot > BeaconChainUtils._getCurrentSlot() - BeaconChainUtils.JUSTIFICATION_DELAY_SLOTS) {
            // We cannot open challenges for slots that are not finalized by Ethereum consensus yet.
            // This is admittedly a bit strict, since 32-slot deep reorgs are very unlikely.
            revert BlockIsNotFinalized();
        }

        // Check that all commitments are for the same slot and signed by the same sender
        // and store the parsed transaction data for each commitment
        TransactionData[] memory transactionsData = new TransactionData[](commitments.length);
        (address txSender, address commitmentSigner, TransactionData memory firstTransactionData) =
            _recoverCommitmentData(commitments[0]);

        transactionsData[0] = firstTransactionData;

        for (uint256 i = 1; i < commitments.length; i++) {
            (address otherTxSender, address otherCommitmentSigner, TransactionData memory otherTransactionData) =
                _recoverCommitmentData(commitments[i]);

            transactionsData[i] = otherTransactionData;

            // check that all commitments are for the same slot
            if (commitments[i].slot != targetSlot) {
                revert UnexpectedMixedSlots();
            }

            // check that all commitments are signed by the same sender
            if (otherTxSender != txSender) {
                revert UnexpectedMixedSenders();
            }

            // check that all commitments are signed by the same signer (aka "operator")
            if (otherCommitmentSigner != commitmentSigner) {
                revert UnexpectedMixedSigners();
            }

            // check that the nonces are strictly sequentially increasing in the bundle
            if (otherTransactionData.nonce != transactionsData[i - 1].nonce + 1) {
                revert UnexpectedNonceOrder();
            }
        }

        // Build the challenge ID: `keccak( keccak(signed tx 1) || keccak(signed tx 2) || ... || le_bytes(slot) )`
        bytes32 challengeID = _computeChallengeID(commitments);

        // Check that a challenge for this commitment bundle does not already exist
        if (challengeIDs.contains(challengeID)) {
            revert ChallengeAlreadyExists();
        }

        // Add the challenge to the set of challenges
        challengeIDs.add(challengeID);
        challenges[challengeID] = Challenge({
            id: challengeID,
            openedAt: Time.timestamp(),
            status: ChallengeStatus.Open,
            targetSlot: targetSlot,
            challenger: msg.sender,
            commitmentSigner: commitmentSigner,
            commitmentReceiver: txSender,
            committedTxs: transactionsData
        });
        emit ChallengeOpened(challengeID, msg.sender, commitmentSigner);
    }

    // ========= CHALLENGE RESOLUTION =========

    function resolveChallenge(bytes32 challengeID, Proof calldata proof) public {
        // Check that the challenge exists
        if (!challengeIDs.contains(challengeID)) {
            revert ChallengeDoesNotExist();
        }

        // The visibility of the BLOCKHASH opcode is limited to the 256 most recent blocks.
        // For simplicity we restrict this to 256 slots even though 256 blocks would be more accurate.
        if (challenges[challengeID].targetSlot < BeaconChainUtils._getCurrentSlot() - BLOCKHASH_EVM_LOOKBACK) {
            revert BlockIsTooOld();
        }

        // Check that the previous block is within the EVM lookback window for block hashes.
        if (
            (proof.inclusionBlockNumber - 1) > block.number
                || (proof.inclusionBlockNumber - 1) < block.number - BLOCKHASH_EVM_LOOKBACK
        ) {
            revert InvalidBlockNumber();
        }

        // Get the trusted block hash for the block number in which the transactions were included.
        bytes32 trustedPreviousBlockHash = blockhash(proof.inclusionBlockNumber);

        // Finally resolve the challenge with the trusted block hash and the provided proofs
        _resolve(challengeID, trustedPreviousBlockHash, proof);
    }

    /// @notice Resolve a challenge that has expired without being resolved.
    /// @dev This will result in the challenge being considered breached, without need to provide
    /// additional proofs of inclusion, as the time window has elapsed.
    /// @param challengeID The ID of the challenge to resolve.
    function resolveExpiredChallenge(
        bytes32 challengeID
    ) public {
        if (!challengeIDs.contains(challengeID)) {
            revert ChallengeDoesNotExist();
        }

        Challenge storage challenge = challenges[challengeID];

        if (challenge.status != ChallengeStatus.Open) {
            revert ChallengeAlreadyResolved();
        }

        if (challenge.openedAt + MAX_CHALLENGE_DURATION >= Time.timestamp()) {
            revert ChallengeNotExpired();
        }

        // If the challenge has expired without being resolved, it is considered breached.
        challenge.status = ChallengeStatus.Breached;
        _transferFullBond(challenge.challenger);
        emit ChallengeBreached(challengeID);
    }

    /// @notice Resolve a challenge by providing proofs of the inclusion of the committed transactions.
    /// @dev Challenges are DEFENDED if the resolver successfully defends the inclusion of the transactions.
    /// In the event of no valid defense in the challenge time window, the challenge is considered BREACHED.
    /// @param challengeID The ID of the challenge to resolve.
    /// @param trustedPreviousBlockHash The block hash of the block before the inclusion block of the committed txs.
    /// @param proof The proof data to resolve the challenge. See `IBoltChallenger.Proof` struct for more details.
    function _resolve(bytes32 challengeID, bytes32 trustedPreviousBlockHash, Proof calldata proof) internal {
        if (!challengeIDs.contains(challengeID)) {
            revert ChallengeDoesNotExist();
        }

        Challenge storage challenge = challenges[challengeID];

        if (challenge.status != ChallengeStatus.Open) {
            revert ChallengeAlreadyResolved();
        }

        if (challenge.openedAt + MAX_CHALLENGE_DURATION < Time.timestamp()) {
            // If the challenge has expired without being resolved, it is considered breached.
            // It's cheaper to call `resolveExpiredChallenge()` directly in this case, but this
            // case should still be handled here for consistency.
            challenge.status = ChallengeStatus.Breached;
            _transferFullBond(challenge.challenger);
            emit ChallengeBreached(challengeID);
            return;
        }

        // Check theintegrity of the proofs
        if (
            proof.txMerkleProofs.length != challenge.committedTxs.length
                || proof.txIndexesInBlock.length != challenge.committedTxs.length
        ) {
            revert InvalidProofsLength();
        }

        // Check the integrity of the trusted block hash
        if (keccak256(proof.previousBlockHeaderRLP) != trustedPreviousBlockHash) {
            revert InvalidBlockHash();
        }

        // Decode the RLP-encoded block header of the previous block to the inclusion block.
        //
        // The previous block's state root is necessary to verify the account had the correct balance and
        // nonce at the top of the inclusion block (before any transactions were applied).
        BlockHeaderData memory previousBlockHeader = _decodeBlockHeaderRLP(proof.previousBlockHeaderRLP);

        // Decode the RLP-encoded block header of the inclusion block.
        //
        // The inclusion block is necessary to extract the transaction root and verify the inclusion of the
        // committed transactions. By checking against the previous block's parent hash we can ensure this
        // is the correct block trusting a single block hash.
        BlockHeaderData memory inclusionBlockHeader = _decodeBlockHeaderRLP(proof.inclusionBlockHeaderRLP);

        // Check that the inclusion block is a child of the previous block
        if (inclusionBlockHeader.parentHash != keccak256(proof.previousBlockHeaderRLP)) {
            revert InvalidParentBlockHash();
        }

        // Decode the account fields by checking the account proof against the state root of the previous block header.
        // The key in the account trie is the account pubkey (address) that sent the committed transactions.
        (bool accountExists, bytes memory accountRLP) = SecureMerkleTrie.get(
            abi.encodePacked(challenge.commitmentReceiver), proof.accountMerkleProof, previousBlockHeader.stateRoot
        );

        if (!accountExists) {
            revert AccountDoesNotExist();
        }

        // Extract the nonce and balance of the account from the RLP-encoded data
        AccountData memory account = _decodeAccountRLP(accountRLP);

        // Loop through each committed transaction and verify its inclusion in the block
        // along with the sender's balance and nonce (starting from the account state at the top of the block).
        for (uint256 i = 0; i < challenge.committedTxs.length; i++) {
            TransactionData memory committedTx = challenge.committedTxs[i];

            if (account.nonce > committedTx.nonce) {
                // The tx sender (aka "challenge.commitmentReceiver") has sent a transaction with a higher nonce
                // than the committed transaction, before the proposer could include it. Consider the challenge
                // defended, as the proposer is not at fault. The bond will be shared between the resolver and
                // commitment signer.
                challenge.status = ChallengeStatus.Defended;
                _transferHalfBond(msg.sender);
                _transferHalfBond(challenge.commitmentSigner);
                emit ChallengeDefended(challengeID);
                return;
            }

            if (account.balance < inclusionBlockHeader.baseFee * committedTx.gasLimit) {
                // The tx sender account doesn't have enough balance to pay for the worst-case baseFee of the committed
                // transaction. Consider the challenge defended, as the proposer is not at fault. The bond will be
                // shared between the resolver and commitment signer.
                challenge.status = ChallengeStatus.Defended;
                _transferHalfBond(msg.sender);
                _transferHalfBond(challenge.commitmentSigner);
                emit ChallengeDefended(challengeID);
                return;
            }

            // Over/Underflow is checked in the previous if statements.
            // This is the same logic applied by the Bolt Sidecar's off-chain checks
            // before deciding to sign a new commitment.
            account.nonce++;
            account.balance -= inclusionBlockHeader.baseFee * committedTx.gasLimit;

            // The key in the transaction trie is the RLP-encoded index of the transaction in the block
            bytes memory txLeaf = RLPWriter.writeUint(proof.txIndexesInBlock[i]);

            // Verify transaction inclusion proof
            //
            // The transactions trie is built with raw leaves, without hashing them first
            // (This denotes why we use `MerkleTrie.get()` as opposed to `SecureMerkleTrie.get()`).
            (bool txExists, bytes memory txRLP) =
                MerkleTrie.get(txLeaf, proof.txMerkleProofs[i], inclusionBlockHeader.txRoot);

            if (!txExists) {
                revert TransactionNotIncluded();
            }

            // Check if the committed transaction hash matches the hash of the included transaction
            if (committedTx.txHash != keccak256(txRLP)) {
                revert WrongTransactionHashProof();
            }
        }

        // If all checks pass, the challenge is considered DEFENDED as the proposer provided valid proofs.
        // The bond will be shared between the resolver and commitment signer.
        challenge.status = ChallengeStatus.Defended;
        _transferHalfBond(msg.sender);
        _transferHalfBond(challenge.commitmentSigner);
        emit ChallengeDefended(challengeID);
    }

    // ========= HELPERS =========

    /// @notice Recover the commitment data from a signed commitment.
    /// @param commitment The signed commitment to recover the data from.
    /// @return txSender The sender of the committed transaction.
    /// @return commitmentSigner The signer of the commitment.
    /// @return transactionData The decoded transaction data of the committed transaction.
    function _recoverCommitmentData(
        SignedCommitment calldata commitment
    ) internal pure returns (address txSender, address commitmentSigner, TransactionData memory transactionData) {
        commitmentSigner = ECDSA.recover(_computeCommitmentID(commitment), commitment.signature);
        TransactionDecoder.Transaction memory decodedTx = commitment.signedTx.decodeEnveloped();
        txSender = decodedTx.recoverSender();
        transactionData = TransactionData({
            txHash: keccak256(commitment.signedTx),
            nonce: decodedTx.nonce,
            gasLimit: decodedTx.gasLimit
        });
    }

    /// @notice Compute the challenge ID for a given set of signed commitments.
    /// @param commitments The signed commitments to compute the ID for.
    /// @return challengeID The computed challenge ID.
    function _computeChallengeID(
        SignedCommitment[] calldata commitments
    ) internal pure returns (bytes32) {
        bytes32[] memory txHashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; i++) {
            txHashes[i] = keccak256(commitments[i].signedTx);
        }

        return keccak256(abi.encodePacked(txHashes, abi.encodePacked(commitments[0].slot)));
    }

    /// @notice Compute the commitment ID for a given signed commitment.
    /// @param commitment The signed commitment to compute the ID for.
    /// @return commitmentID The computed commitment ID.
    function _computeCommitmentID(
        SignedCommitment calldata commitment
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(commitment.signedTx), abi.encodePacked(commitment.slot)));
    }

    /// @notice Decode the block header fields from an RLP-encoded block header.
    /// @param headerRLP The RLP-encoded block header to decode
    function _decodeBlockHeaderRLP(
        bytes calldata headerRLP
    ) internal pure returns (BlockHeaderData memory blockHeader) {
        RLPReader.RLPItem[] memory headerFields = headerRLP.toRLPItem().readList();

        blockHeader.parentHash = headerFields[0].readBytes32();
        blockHeader.stateRoot = headerFields[3].readBytes32();
        blockHeader.txRoot = headerFields[4].readBytes32();
        blockHeader.blockNumber = headerFields[8].readUint256();
        blockHeader.timestamp = headerFields[11].readUint256();
        blockHeader.baseFee = headerFields[15].readUint256();
    }

    /// @notice Decode the account fields from an RLP-encoded account.
    /// @param accountRLP The RLP-encoded account to decode
    /// @return account The decoded account data.
    function _decodeAccountRLP(
        bytes memory accountRLP
    ) internal pure returns (AccountData memory account) {
        RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();

        account.nonce = accountFields[0].readUint256();
        account.balance = accountFields[1].readUint256();
    }

    /// @notice Transfer the full challenge bond to a recipient.
    /// @param recipient The address to transfer the bond to.
    function _transferFullBond(
        address recipient
    ) internal {
        (bool success,) = payable(recipient).call{value: COMMITMENT_BOND}("");
        if (!success) {
            revert BondTransferFailed();
        }
    }

    /// @notice Transfer half of the challenge bond to a recipient.
    /// @param recipient The address to transfer half of the bond to.
    function _transferHalfBond(
        address recipient
    ) internal {
        (bool success,) = payable(recipient).call{value: COMMITMENT_BOND / 2}("");
        if (!success) {
            revert BondTransferFailed();
        }
    }
}
