// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";

import {SecureMerkleTrie} from "../lib/trie/SecureMerkleTrie.sol";
import {MerkleTrie} from "../lib/trie/MerkleTrie.sol";
import {RLPReader} from "../lib/rlp/RLPReader.sol";
import {BeaconChainUtils} from "../lib/BeaconChainUtils.sol";
import {IBoltChallenger} from "../interfaces/IBoltChallenger.sol";

contract BoltChallenger is IBoltChallenger {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // ========= STORAGE =========

    /// @notice The set of existing unique challenge IDs.
    EnumerableSet.Bytes32Set internal challengeIDs;

    /// @notice The mapping of challenge IDs to their respective challenges.
    mapping(bytes32 => Challenge) public challenges;

    // ========= CONSTANTS =========

    /// @notice The challenge bond required to open a challenge.
    uint256 public constant CHALLENGE_BOND = 1 ether;

    // ========= CONSTRUCTOR =========

    constructor() {}

    // ========= CHALLENGE OPENING =========

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
            resolved: false,
            challenger: msg.sender,
            target: commitmentSigner,
            commitment: commitment
        });

        emit ChallengeOpened(commitmentID, msg.sender, commitmentSigner);
    }

    // ========= CHALLENGE RESOLUTION =========

    function resolveChallenge(
        uint256 challengeId
    ) public {
        // unimplemented!();
    }

    // ========= HELPERS =========

    /// @notice Decode the block header fields from an RLP-encoded block header.
    /// @param headerRLP The RLP-encoded block header to decode
    function _decodeBlockHeaderRLP(
        bytes calldata headerRLP
    ) internal pure returns (bytes32 transactionsRoot, uint256 blockNumber, uint256 timestamp, uint256 baseFee) {
        RLPReader.RLPItem[] memory headerFields = headerRLP.toRLPItem().readList();

        transactionsRoot = headerFields[4].readBytes32();
        blockNumber = headerFields[8].readUint256();
        timestamp = headerFields[11].readUint256();
        baseFee = headerFields[15].readUint256();
    }

    function _decodeAccountRLP(
        bytes calldata accountRLP
    ) internal pure returns (uint256 nonce, uint256 balance) {
        RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();

        nonce = accountFields[0].readUint256();
        balance = accountFields[1].readUint256();
    }

    function _decodeTransactionRLP(
        bytes calldata transactionRLP
    ) internal pure returns (uint256 nonce, uint256 gasPrice, uint256 gasLimit) {
        RLPReader.RLPItem[] memory transactionFields = transactionRLP.toRLPItem().readList();

        nonce = transactionFields[0].readUint256();
        gasPrice = transactionFields[1].readUint256();
        gasLimit = transactionFields[2].readUint256();
    }

    // /// @notice Prove the account data of an account at a given state root.
    // /// @dev This function assumes that the provided state root and account proof match.
    // /// @param account The account address to prove.
    // /// @param trustedStateRoot The state root to prove against.
    // /// @param accountProof The MPT account proof to prove the account data.
    // /// @return nonce The nonce of the account at the given state root height.
    // /// @return balance The balance of the account at the given state root height.
    // function proveAccountData(
    //     address account,
    //     bytes32 trustedStateRoot,
    //     bytes calldata accountProof
    // ) public pure returns (uint256 nonce, uint256 balance) {
    //     (bool exists, bytes memory accountRLP) =
    //         SecureMerkleTrie.get(abi.encodePacked(account), accountProof, trustedStateRoot);

    //     if (!exists) {
    //         revert AccountDoesNotExist();
    //     }

    //     // RLP decode the account and extract the nonce and balance
    //     RLPReader.RLPItem[] memory accountFields = accountRLP.toRLPItem().readList();
    //     nonce = accountFields[0].readUint256();
    //     balance = accountFields[1].readUint256();
    // }
}
