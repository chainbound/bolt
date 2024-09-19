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
    uint256 public constant CHALLENGE_BOND = 1 ether;

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

    // Q: should we add a commit-reveal scheme to prevent frontrunning to steal slashing rewards?
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

        if (commitment.slot > BeaconChainUtils._getCurrentSlot() - BeaconChainUtils.FINALIZATION_DELAY_SLOTS) {
            // We cannot open challenges for slots that are not finalized yet.
            // This is admittedly a bit strict, since 64-slot deep reorgs are very unlikely.
            revert BlockIsNotFinalized();
        }

        // Reconstruct the commitment digest: `keccak( keccak(signed tx) || le_bytes(slot) )`
        bytes32 commitmentID =
            keccak256(abi.encodePacked(keccak256(commitment.signedTx), abi.encodePacked(commitment.slot)));

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

    function resolveRecentChallenge(bytes32 challengeID, Proof calldata proof) public {
        // Check that the challenge exists
        if (!challengeIDs.contains(challengeID)) {
            revert ChallengeDoesNotExist();
        }

        // The visibility of the BLOCKHASH opcode is limited to the 256 most recent blocks.
        // For simplicity we restrict this to 256 slots even though 256 blocks would be more accurate.
        if (challenges[challengeID].commitment.slot < BeaconChainUtils._getCurrentSlot() - BLOCKHASH_EVM_LOOKBACK) {
            revert BlockIsTooOld();
        }

        // Check that the block number is within the EVM lookback window for block hashes
        if (proof.blockNumber > block.number || proof.blockNumber < block.number - BLOCKHASH_EVM_LOOKBACK) {
            revert InvalidBlockNumber();
        }

        // Get the trusted block hash for the block number in which the transaction was included.
        bytes32 trustedBlockHash = blockhash(proof.blockNumber);

        // Finally resolve the challenge with the trusted block hash and the provided proofs
        _resolve(challengeID, trustedBlockHash, proof);
    }

    // Resolving a historical challenge requires acquiring a block hash from an alternative source
    // from the EVM. This is because the BLOCKHASH opcode is limited to the 256 most recent blocks.
    function resolveChallenge(bytes32 challengeID, Proof calldata proof) public {
        // unimplemented!();
    }

    /// @notice Resolve a challenge that has expired without being resolved.
    /// @dev This will result in the challenge being considered lost, without need to provide 
    /// additional proofs of inclusion, as the time window has elapsed.
    function resolveExpiredChallenge(bytes32 challengeID) public {
        if (!challengeIDs.contains(challengeID)) {
            revert ChallengeDoesNotExist();
        }

        // The challenge is assumed to exist at this point, so we can safely access it.
        Challenge storage challenge = challenges[challengeID];

        if (challenge.status != ChallengeStatus.Open) {
            revert ChallengeAlreadyResolved();
        }

        if (challenge.openedAt + MAX_CHALLENGE_DURATION >= Time.timestamp()) {
            revert ChallengeNotExpired();
        }

        // If the challenge has expired without being resolved, it is considered lost.
        challenge.status = ChallengeStatus.Lost;
        _transferFullBond(challenge.challenger);
        emit ChallengeLost(challengeID);
    }

    /// @notice Resolve a challenge by providing proofs of the inclusion of the committed transaction.
    /// @dev Challenges are DEFENDED if the resolver successfully defends the inclusion of the transaction,
    /// and LOST if the challenger successfully demonstrates that the inclusion commitment was breached or
    /// enough time has passed without proper resolution.
    ///
    /// q: should we also have a commit-reveal scheme for resolutions to avoid frontrunning to steal bonds?
    function _resolve(bytes32 challengeID, bytes32 trustedBlockHash, Proof calldata proof) internal {
        // The challenge is assumed to exist at this point, so we can safely access it.
        Challenge storage challenge = challenges[challengeID];

        if (challenge.status != ChallengeStatus.Open) {
            revert ChallengeAlreadyResolved();
        }

        if (challenge.openedAt + MAX_CHALLENGE_DURATION < Time.timestamp()) {
            // If the challenge has expired without being resolved, it is considered lost.
            challenge.status = ChallengeStatus.Lost;
            _transferFullBond(challenge.challenger);
            emit ChallengeLost(challengeID);
            return;
        }

        // Verify the validity of the header against the trusted block hash.
        if (keccak256(proof.blockHeaderRLP) != trustedBlockHash) {
            revert InvalidBlockHash();
        }

        // Decode the RLP-encoded block header fields
        BlockHeaderData memory blockHeader = _decodeBlockHeaderRLP(proof.blockHeaderRLP);

        // Recover the sender of the committed raw signed transaction. It will be the account to prove existence of.
        TransactionDecoder.Transaction memory decodedTx = challenge.commitment.signedTx.decodeEnveloped();
        address accountToProve = decodedTx.recoverSender();

        // Decode the account fields by checking the account proof against the state root of the block header
        (bool accountExists, bytes memory accountRLP) =
            SecureMerkleTrie.get(abi.encodePacked(accountToProve), proof.accountMerkleProof, blockHeader.stateRoot);

        if (!accountExists) {
            revert AccountDoesNotExist();
        }

        AccountData memory account = _decodeAccountRLP(accountRLP);

        if (account.nonce > decodedTx.nonce) {
            // The sender (accountToProve) has sent a transaction with a higher nonce than the committed
            // transaction, before the proposer could include it. Consider the challenge defended, as the
            // proposer is not at fault. The bond will be shared between the resolver and commitment signer.
            challenge.status = ChallengeStatus.Defended;
            _transferHalfBond(msg.sender);
            _transferHalfBond(challenge.target);
            emit ChallengeDefended(challengeID);
            return;
        } else if (account.nonce < decodedTx.nonce) {
            // Q: is this a valid case? technically the proposer would be at fault for accepting a commitment of an
            // already included transaction. TBD.
        }

        if (account.balance < blockHeader.baseFee * decodedTx.gasLimit) {
            // The account does not have enough balance to pay for the worst-case base fee of the committed transaction.
            // Consider the challenge defended, as the proposer is not at fault. The bond will be shared between the 
            // resolver and commitment signer.
            challenge.status = ChallengeStatus.Defended;
            _transferHalfBond(msg.sender);
            _transferHalfBond(challenge.target);
            emit ChallengeDefended(challengeID);
            return;
        }

        // The key in the transaction trie is the RLP-encoded index of the transaction in the block
        bytes memory txLeaf = RLPWriter.writeUint(proof.txIndexInBlock);

        // Verify transaction inclusion proof
        // Note: the transactions trie is built with raw leaves, without hashing them first.
        // This denotes why we use `MerkleTrie.get()` as opposed to `SecureMerkleTrie.get()` here.
        (bool txExists, bytes memory txRLP) = MerkleTrie.get(txLeaf, proof.txMerkleProof, blockHeader.txRoot);

        if (!txExists) {
            revert TransactionNotIncluded();
        }

        // Decode the txRLP and check if it matches the committed transaction
        // TODO: q: is txRLP also envelope encoded? if not, this check will fail.
        if (keccak256(challenge.commitment.signedTx) != keccak256(txRLP)) {
            revert WrongTransactionHashProof();
        }

        // If all checks pass, the challenge is considered defended as the proposer defended with valid proofs.
        // The bond will be shared between the resolver and commitment signer.
        challenge.status = ChallengeStatus.Defended;
        _transferHalfBond(msg.sender);
        _transferHalfBond(challenge.target);
        emit ChallengeDefended(challengeID);
    }

    // ========= HELPERS =========

    /// @notice Decode the block header fields from an RLP-encoded block header.
    /// @param headerRLP The RLP-encoded block header to decode
    function _decodeBlockHeaderRLP(
        bytes calldata headerRLP
    ) internal pure returns (BlockHeaderData memory blockHeader) {
        RLPReader.RLPItem[] memory headerFields = headerRLP.toRLPItem().readList();

        blockHeader.stateRoot = headerFields[3].readBytes32();
        blockHeader.txRoot = headerFields[4].readBytes32();
        blockHeader.blockNumber = headerFields[8].readUint256();
        blockHeader.timestamp = headerFields[11].readUint256();
        blockHeader.baseFee = headerFields[15].readUint256();
    }

    function _decodeAccountRLP(
        bytes memory accountRLP
    ) internal pure returns (AccountData memory account) {
        RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();

        account.nonce = accountFields[0].readUint256();
        account.balance = accountFields[1].readUint256();
    }

    function _transferFullBond(address recipient) internal {
        (bool success, ) = payable(recipient).call{value: CHALLENGE_BOND}("");
        if (!success) {
            revert BondTransferFailed();
        }
    }

    function _transferHalfBond(address recipient) internal {
        (bool success, ) = payable(recipient).call{value: CHALLENGE_BOND / 2}("");
        if (!success) {
            revert BondTransferFailed();
        }
    }
}
