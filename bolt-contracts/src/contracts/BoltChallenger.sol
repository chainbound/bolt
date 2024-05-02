// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IProver} from "relic-sdk/packages/contracts/interfaces/IProver.sol";
import {IReliquary} from "relic-sdk/packages/contracts/interfaces/IReliquary.sol";
import {Facts} from "relic-sdk/packages/contracts/lib/Facts.sol";
import {FactSigs} from "relic-sdk/packages/contracts/lib/FactSigs.sol";
import {CoreTypes} from "relic-sdk/packages/contracts/lib/CoreTypes.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IBoltRegistry} from "../interfaces/IBoltRegistry.sol";

contract BoltChallenger is IBoltChallenger {
    /// @notice The max duration of a challenge, after which it is considered resolved
    /// even if no one has provided a valid proof for it.
    uint256 public constant CHALLENGE_DURATION = 7 days;

    /// @notice The bond required to open a challenge. This is to avoid spamming
    /// and DOS attacks on proposers. If a challenge is successful, the bond is
    /// returned to the challenger, otherwise it is sent to the based proposer.
    uint256 public constant CHALLENGE_BOND = 1 ether;

    /// @notice The address of the BeaconRoots contract
    /// @dev See EIP-4788 for more info
    address internal constant BEACON_ROOTS_CONTRACT = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @notice The max number of slots that can pass after which a challenge cannot
    /// be opened anymore. This corresponds to about 1 day.
    /// @dev This is a limiatation of the `BEACON_ROOTS` contract (see EIP-4788 for more info).
    uint256 internal constant CHALLENGE_RETROACTIVE_TARGET_SLOT_WINDOW = 8190;

    /// @notice The duration of a slot in seconds
    uint256 internal constant SLOT_TIME = 12;

    /// @notice The timestamp of the genesis of the eth2 chain
    uint256 internal constant ETH2_GENESIS_TIMESTAMP = 1606824023;

    /// @notice The address of the BoltRegistry contract
    IBoltRegistry public immutable boltRegistry;

    /// @notice The address of the Relic Reliquary contract
    IReliquary public immutable reliquary;

    /// @notice The address of the block header prover contract
    IProver public immutable blockHeaderProver;

    // Struct to hold all challenge details in stoage
    struct Challenge {
        // The address of the based proposer being challenged
        address basedProposer;
        // The signed commitment that the proposer supposedly failed to honor
        SignedCommitment signedCommitment;
        // The address of the challenger
        address challenger;
        // The beacon root object of the target slot's block header.
        // This is directly fetched from the on-chain BEACON_ROOTS oracle.
        bytes32 targetSlotBeaconRoot;
        // The status of the challenge
        ChallengeStatus status;
        // The timestamp at which the challenge was opened
        uint256 openTimestamp;
    }

    /// @notice The struct to hold the inclusion commitment, including the proposer's signature
    /// @dev there can be different kinds of commitments, this is just an example
    struct SignedCommitment {
        uint256 slot;
        bytes signedRawTransaction;
        bytes signature;
    }

    /// @notice The mapping of challenges, indexed by the unique ID of their inclusion commitment
    mapping(bytes32 => Challenge) public challenges;

    /// @notice Constructor
    /// @param _boltRegistry The address of the BoltRegistry contract
    /// @param _reliquary The address of the Relic Reliquary contract
    /// @param _blockHeaderProver The address of the Relic block header prover contract
    constructor(address _boltRegistry, address _reliquary, address _blockHeaderProver) {
        boltRegistry = IBoltRegistry(_boltRegistry);
        reliquary = IReliquary(_reliquary);

        // Check if the provided prover is a valid prover
        reliquary.checkProver(reliquary.provers(_blockHeaderProver));
        blockHeaderProver = IProver(_blockHeaderProver);
    }

    /// @notice Challenge a proposer if it hasn't honored a preconfirmation.
    /// @notice A challenge requires a bond to be transferred to this contract to avoid spamming.
    /// @param _basedProposer The address of the proposer to challenge
    /// @param _signedCommitment The signed commitment that the proposer is getting challenged for
    function challenge(address _basedProposer, SignedCommitment calldata _signedCommitment) public payable {
        // First sanity checks
        if (_basedProposer == address(0) || _signedCommitment.slot == 0) {
            revert InvalidChallenge();
        }

        // Check if there is a sufficient bond attached to the transaction
        if (msg.value < CHALLENGE_BOND) {
            revert InsufficientBond();
        } else if (msg.value > CHALLENGE_BOND) {
            // Refund the excess bond
            payable(msg.sender).transfer(msg.value - CHALLENGE_BOND);
        }

        // Check if the target slot is not too far in the past
        if (_getCurrentSlot() - _signedCommitment.slot > CHALLENGE_RETROACTIVE_TARGET_SLOT_WINDOW) {
            // Challenges cannot be opened for slots that are too far in the past, because we rely
            // on the BEACON_ROOTS contract to fetch the beacon block root for the target slot.
            revert TargetSlotTooFarInThePast();
        }

        // Check if the proposer is an active based proposer
        if (!boltRegistry.isActiveBasedProposer(_basedProposer)) {
            revert Unauthorized();
        }

        bytes32 commitmentID = _getCommitmentID(_signedCommitment);

        // Check if a challenge already exists for the given commitment
        // Challenge duplicates are not allowed
        if (challenges[commitmentID].basedProposer != address(0)) {
            revert ChallengeAlreadyExists();
        }

        // Check if the signed commitment was made by the challenged based proposer
        if (_recoverCommitmentSigner(commitmentID, _signedCommitment.signature) != _basedProposer) {
            revert Unauthorized();
        }

        // Note: we don't check if the based proposer was actually scheduled for proposal at their
        // target slot. Proposers are expected to not preconfirm if they are not the scheduled proposer,
        // as they would be penalized for it.

        // Get the beacon block root for the target slot. We store it in the Challenge so that
        // it can be used even after 8192 slots have passed (the limit of the BEACON_ROOTS contract)
        bytes32 beaconBlockRoot = _getBeaconBlockRoot(_signedCommitment.slot);

        // ==== Create a new challenge ====

        challenges[commitmentID] = Challenge({
            basedProposer: _basedProposer,
            challenger: msg.sender,
            signedCommitment: _signedCommitment,
            targetSlotBeaconRoot: beaconBlockRoot,
            status: ChallengeStatus.Pending,
            openTimestamp: block.timestamp
        });

        emit NewChallenge(_basedProposer, commitmentID, _signedCommitment.slot);
    }

    /// @notice Resolve a challenge by providing a valid proof for the preconfirmation.
    /// @param _challengeID The unique ID of the challenge to resolve
    /// @dev anyone can call this function on a pending challenge, but only the challenged based proposer
    /// @dev will be able to provide a valid proof to counter it. If the challenge expires or the proof is invalid,
    /// @dev the challenger will be rewarded with the bond + a portion of the slashed amount.
    function resolveChallenge(
        bytes32 _challengeID,
        bytes calldata _blockHeaderProof,
        uint256 _transactionIndex,
        bytes32[] calldata _inclusionProof
    ) public {
        Challenge storage challenge = challenges[_challengeID];

        // Check if the challenge exists
        if (challenge.basedProposer == address(0)) {
            revert ChallengeNotFound();
        }

        // Check if the challenge is still pending
        if (challenge.status != ChallengeStatus.Pending) {
            revert ChallengeAlreadyResolved();
        }

        // Check if the challenge has expired.
        // Note: we consider the challenge successful if it expires without being resolved.
        // This means that the validator failed to honor the commitment and will get slashed.
        if (block.timestamp - challenge.openTimestamp > CHALLENGE_DURATION) {
            challenge.status = ChallengeStatus.Resolved;

            // TODO: slash the based proposer and return the full bond to the challenger.
            // Part of the slashed amount will also be returned to the challenger as a reward.
            // This is the reason we don't have access control in this function.

            emit ChallengeResolved(_challengeID, ChallengeResult.Success);

            return;
        }

        // From here on, we assume the function was called by the based proposer
        if (msg.sender != challenge.basedProposer) {
            revert Unauthorized();
        }

        // Derive the transactions root of the target block from the block header proof
        (bytes32 transactionsRoot, uint256 blockTimestamp) = _deriveBlockHeaderInfo(_blockHeaderProof);

        // TODO: prove that the nonce of the sender that was preconfirmed was valid (aka not too low)
        // at the time of the based proposer's slot. This is to prevent an attack to make the preconfirmation
        // invalid by nonce.

        // TODO: we could use the beacon root oracle to check that the based proposer proposed a block
        // at the target slot or if it was reorged. This could be useful to differentiate between a
        // safety vs liveness fault.

        // Check if the block header timestamp matches the target slot
        // TODO: handle the case where the transaction was included in a previous block
        // before the preconfirmer's slot.
        if (blockTimestamp != challenge.signedCommitment.slot * SLOT_TIME + ETH2_GENESIS_TIMESTAMP) {
            revert WrongBlockHeader();
        }

        // Check if the transactions root matches the signed commitment
        uint256 generalizedIndex = 1_048_576 + _transactionIndex;
        bytes32 leaf = SSZ._hashTreeRoot(); // TODO: complete hash tree root of the transaction (by chunks)
        bool isValid = SSZ._verifyProof(_inclusionProof, transactionsRoot, leaf, generalizedIndex);

        if (!isValid) {
            // The challenge was successful: the proposer failed to honor the preconfirmation
            // TODO: slash
            challenge.status = ChallengeStatus.Resolved;
            emit ChallengeResolved(_challengeID, ChallengeResult.Failure);
        } else {
            // The challenge was unsuccessful: the proposer honored the preconfirmation
            // TODO: return the bond to the proposer
            challenge.status = ChallengeStatus.Resolved;
            emit ChallengeResolved(_challengeID, ChallengeResult.Success);
        }
    }

    /// @notice Fetch trustlessly valid block header data
    /// @param _proof The proof of the block header
    /// @return The transactions root and the timestamp of the block
    function _deriveBlockHeaderInfo(bytes calldata _proof) internal pure returns (bytes32, uint256) {
        // TODO: handle fee for proving. make payable?

        Fact memory fact = blockHeaderProver.prove(_proof, false);
        CoreTypes.BlockHeaderData memory blockHeader = abi.decode(fact.data, (CoreTypes.BlockHeaderData));

        if (FactSignature.unwrap(fact.sig) != FactSigs.blockHeaderSig(blockHeader.number)) {
            revert UnexpectedFactSignature();
        }

        return (blockHeader.TxHash, blockHeader.Time);
    }

    /// @notice Recover the signer of a commitment
    /// @param _commitmentSignature The signature of the commitment
    /// @param _commitmentHash The keccak hash of an unsigned message
    function _recoverCommitmentSigner(bytes32 _commitmentHash, bytes calldata _commitmentSignature)
        internal
        pure
        returns (address)
    {
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(_commitmentHash, _commitmentSignature);
        if (err != ECDSA.RecoverError.NoError || signer == address(0)) {
            revert Unauthorized();
        }

        return signer;
    }

    /// @notice Hashes the inclusion commitment to a unique ID to index the challenge
    function _getCommitmentID(SignedCommitment memory _commitment) internal pure returns (bytes32) {
        return
            keccak256(abi.encodePacked(_commitment.slot, _commitment.transactionHash, _commitment.signedRawTransaction));
    }

    /// @notice Get the current slot number
    /// @return The current slot number
    function _getCurrentSlot() internal view returns (uint256) {
        return (block.timestamp - ETH2_GENESIS_TIMESTAMP) / SLOT_TIME;
    }

    /// @notice Get the beacon block root for a given slot
    /// @param _slot The slot number
    /// @return The beacon block root
    function _getBeaconBlockRoot(uint256 _slot) internal view returns (bytes32) {
        uint256 slotTimestamp = ETH2_GENESIS_TIMESTAMP + _slot * SLOT_TIME;

        (bool success, bytes memory data) = BEACON_ROOTS_CONTRACT.staticcall(abi.encode(slotTimestamp));

        if (!success || data.length == 0) {
            revert BeaconRootNotFound();
        }

        return abi.decode(data, (bytes32));
    }
}
