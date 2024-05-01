// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IBoltRegistry} from "../interfaces/IBoltRegistry.sol";

contract BoltChallenger {
    using ECDSA for bytes32;

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

    struct Challenge {
        // The address of the based proposer that has been challenged
        address basedProposer;
        // The address of the challenger
        address challenger;
        // The slot at which the preconfirmation was targeted
        uint256 targetSlot;
        // The beacon root object of the target slot's block header
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
        bytes32 transactionHash;
        bytes signedRawTransaction;
        bytes signature;
    }

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

    /// @notice The mapping of challenges, indexed by the unique ID of their inclusion commitment
    mapping(bytes32 => Challenge) public challenges;

    error ChallengeAlreadyExists();
    error InsufficientBond();
    error Unauthorized();
    error InvalidChallenge();
    error BeaconRootNotFound();
    error TargetSlotTooFarInThePast();

    /// @notice Event emitted when a new challenge is opened
    event NewChallenge(address indexed basedProposer, uint256 targetSlot);

    /// @notice Constructor
    /// @param _boltRegistry The address of the BoltRegistry contract
    constructor(address _boltRegistry) {
        boltRegistry = IBoltRegistry(_boltRegistry);
    }

    /// @notice Challenge a proposer if it hasn't honored a preconfirmation.
    /// @notice A challenge requires a bond to be transferred to this contract to avoid spamming.
    /// @param _proposer The address of the proposer to challenge
    /// @param _signedCommitment The signed commitment that the proposer supposedly failed to honor
    function challenge(address _proposer, SignedCommitment calldata _signedCommitment) public payable {
        // First sanity checks
        if (_proposer == address(0) || _signedCommitment.slot == 0) {
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
            revert TargetSlotTooFarInThePast();
        }

        // Check if the proposer is an active based proposer
        if (!boltRegistry.isActivrBasedProposer(_proposer)) {
            revert Unauthorized();
        }

        bytes32 commitmentHash = _getCommitmentID(_signedCommitment);

        // Check if a challenge already exists for the given commitment
        // Challenge duplicates are not allowed
        if (challenges[commitmentHash].basedProposer != address(0)) {
            revert ChallengeAlreadyExists();
        }

        // Check if the signed commitment recovers to the correct based proposer
        if (_recoverCommitmentSigner(_signedCommitment.signature, commitmentHash) != _proposer) {
            revert Unauthorized();
        }

        // Note: we don't check if the based proposer was actually scheduled for proposal at their
        // target slot. Proposers are expected to not preconfirm if they are not the scheduled proposer,
        // as they would be penalized for it.

        // Get the beacon block root for the target slot
        bytes32 beaconBlockRoot = _getBeaconBlockRoot(_signedCommitment.slot);

        // ==== Create a new challenge ====

        Challenge memory newChallenge = Challenge({
            basedProposer: _proposer,
            challenger: msg.sender,
            targetSlot: _signedCommitment.slot,
            targetSlotBeaconRoot: beaconBlockRoot,
            status: ChallengeStatus.Pending,
            openTimestamp: block.timestamp
        });

        challenges[commitmentHash] = newChallenge;

        emit NewChallenge(_proposer, _signedCommitment.slot);
    }

    function resolveChallenge() public {
        // TODO
    }

    /// @notice Recover the signer of a commitment
    /// @param _commitmentSignature The signature of the commitment
    /// @param _commitmentHash The hash of the unsigned message
    function _recoverCommitmentSigner(bytes calldata _commitmentSignature, bytes32 _commitmentHash)
        internal
        pure
        returns (address)
    {
        (address signer, ECDSA.RecoverError err,) = _commitmentHash.tryRecover(_commitmentSignature);
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
