// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IProver} from "relic-sdk/packages/contracts/interfaces/IProver.sol";
import {IReliquary} from "relic-sdk/packages/contracts/interfaces/IReliquary.sol";
import {Facts, Fact, FactSignature} from "relic-sdk/packages/contracts/lib/Facts.sol";
import {FactSigs} from "relic-sdk/packages/contracts/lib/FactSigs.sol";
import {CoreTypes} from "relic-sdk/packages/contracts/lib/CoreTypes.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IBoltRegistry} from "../interfaces/IBoltRegistry.sol";
import {IBoltChallenger} from "../interfaces/IBoltChallenger.sol";

import {SSZ} from "../lib/SSZ.sol";
import {SSZContainers} from "../lib/SSZContainers.sol";
import {BeaconChainUtils} from "../lib/BeaconChainUtils.sol";

contract BoltChallenger is IBoltChallenger {
    /// @notice The max duration of a challenge, after which it is considered resolved
    /// even if no one has provided a valid proof for it.
    uint256 public constant MAX_CHALLENGE_DURATION = 7 days;

    /// @notice The bond required to open a challenge. This is to avoid spamming
    /// and DOS attacks on proposers. If a challenge is successful, the bond is
    /// returned to the challenger, otherwise it is sent to the based proposer.
    uint256 public constant CHALLENGE_BOND = 1 ether;

    /// @notice The max number of slots that can pass after which a challenge cannot
    /// be opened anymore. This corresponds to about 1 day.
    /// @dev This is a limitation of the `BEACON_ROOTS` contract (see EIP-4788 for more info).
    uint256 internal constant CHALLENGE_RETROACTIVE_TARGET_SLOT_WINDOW = 8190;

    /// @notice The address of the BoltRegistry contract
    IBoltRegistry public immutable boltRegistry;

    /// @notice The address of the Relic Reliquary contract
    IReliquary public immutable reliquary;

    /// @notice The address of the block header prover contract
    IProver public immutable blockHeaderProver;

    /// @notice The address of the account info prover contract
    IProver public immutable accountInfoProver;

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
        uint256 nonce;
        uint256 gasUsed;
        bytes32 transactionHash;
        bytes signedRawTransaction;
        bytes signature;
    }

    /// @notice The mapping of challenges, indexed by the unique ID of their inclusion commitment
    mapping(bytes32 => Challenge) public challenges;

    /// @notice Constructor
    /// @param _boltRegistry The address of the BoltRegistry contract
    /// @param _reliquary The address of the Relic Reliquary contract
    /// @param _blockHeaderProver The address of the Relic block header prover contract
    constructor(address _boltRegistry, address _reliquary, address _blockHeaderProver, address _accountInfoProver) {
        boltRegistry = IBoltRegistry(_boltRegistry);
        reliquary = IReliquary(_reliquary);

        // Check if the provided provers are valid
        // TODO: readd this for mainnet deployment (currently disabled for testing)
        // reliquary.checkProver(reliquary.provers(_blockHeaderProver));
        // reliquary.checkProver(reliquary.provers(_accountInfoProver));

        blockHeaderProver = IProver(_blockHeaderProver);
        accountInfoProver = IProver(_accountInfoProver);
    }

    /// @notice Challenge a proposer if it hasn't honored a preconfirmation.
    /// @notice A challenge requires a bond to be transferred to this contract to avoid spamming.
    /// @param _basedProposer The address of the proposer to challenge
    /// @param _signedCommitment The signed commitment that the proposer is getting challenged for
    function challengeProposer(address _basedProposer, SignedCommitment calldata _signedCommitment) public payable {
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
        if (
            BeaconChainUtils._getSlotFromTimestamp(block.timestamp) - _signedCommitment.slot
                > CHALLENGE_RETROACTIVE_TARGET_SLOT_WINDOW
        ) {
            // Challenges cannot be opened for slots that are too far in the past, because we rely
            // on the BEACON_ROOTS ring buffer to be available for the challenge to be resolved.
            revert TargetSlotTooFarInThePast();
        }

        // Check if the proposer is an active based proposer
        if (!boltRegistry.isActiveBasedProposer(_basedProposer)) {
            revert InvalidProposerAddress();
        }

        bytes32 commitmentID = _getCommitmentID(_signedCommitment);

        // Check if a challenge already exists for the given commitment
        // Challenge duplicates are not allowed
        if (challenges[commitmentID].basedProposer != address(0)) {
            revert ChallengeAlreadyExists();
        }

        // Check if the signed commitment was made by the challenged based proposer
        if (_recoverCommitmentSigner(commitmentID, _signedCommitment.signature) != _basedProposer) {
            revert InvalidCommitmentSigner();
        }

        // Note: we don't check if the based proposer was actually scheduled for proposal at their
        // target slot. Proposers are expected to not preconfirm if they are not the scheduled proposer,
        // as they would be penalized for it.

        // Get the beacon block root for the target slot. We store it in the Challenge so that
        // it can be used even after 8192 slots have passed (the limit of the BEACON_ROOTS contract)
        bytes32 beaconBlockRoot = BeaconChainUtils._getBeaconBlockRoot(_signedCommitment.slot);

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
    /// @param _blockHeaderProof The proof of the block header of the target slot
    /// @param _accountDataProof The proof of the account data of the preconfirmed sender
    /// @param _transactionIndex The index of the transaction in the block
    /// @param _inclusionProof The Merkle proof of the transaction's inclusion in the block
    /// @dev anyone can call this function on a pending challenge, but only the challenged based proposer
    /// @dev will be able to provide a valid proof to counter it. If the challenge expires or the proof is invalid,
    /// @dev the challenger will be rewarded with the bond + a portion of the slashed amount.
    function resolveChallenge(
        bytes32 _challengeID,
        bytes calldata _blockHeaderProof,
        bytes calldata _accountDataProof,
        uint256 _transactionIndex,
        bytes32[] calldata _inclusionProof
    ) public {
        Challenge memory challenge = challenges[_challengeID];

        // Check if the challenge exists
        if (challenge.basedProposer == address(0)) {
            revert ChallengeNotFound();
        }

        // Check if the challenge is still pending
        if (challenge.status != ChallengeStatus.Pending) {
            revert ChallengeAlreadyResolved();
        }

        // Check if the challenge has expired.
        // This means that the validator failed to honor the commitment and will get slashed.
        if (block.timestamp - challenge.openTimestamp > MAX_CHALLENGE_DURATION) {
            // Part of the slashed amount will also be returned to the challenger as a reward.
            // This is the reason we don't have access control in this function.
            // TODO: slash the based proposer.
            _onChallengeSuccess(_challengeID);
            return;
        }

        // From here on, we assume the function was called by the based proposer
        if (msg.sender != challenge.basedProposer) {
            revert Unauthorized();
        }

        // Derive the block header data of the target block from the block header proof
        CoreTypes.BlockHeaderData memory verifiedHeader = _deriveBlockHeaderInfo(_blockHeaderProof);

        // Derive the preconfirmed sender's account data from the account data proof
        CoreTypes.AccountData memory verifiedAccount = _deriveAccountData(_accountDataProof, verifiedHeader.Number);

        // Check that the nonce of the preconfirmed sender is valid (not too low)
        // at the time of the based proposer's slot.
        if (verifiedAccount.Nonce > challenge.signedCommitment.nonce) {
            // consider the challenge unsuccessful: the user sent a transaction before
            // the proposer could include it, as such it is not at fault.
            _onChallengeFailure(_challengeID);
            return;
        }

        // Check that the balance of the preconfirmed sender is enough to cover the base fee
        // of the block.
        if (verifiedAccount.Balance < challenge.signedCommitment.gasUsed * verifiedHeader.BaseFee) {
            // consider the challenge unsuccessful: the user doesn't have enough balance to cover the gas
            // thus invalidating the preconfirmation: the proposer is not at fault.
            _onChallengeFailure(_challengeID);
            return;
        }

        // TODO: we could use the beacon root oracle to check that the based proposer proposed a block
        // at the target slot or if it was reorged. This could be useful to differentiate between a
        // safety vs liveness fault.

        // Check if the block header timestamp is UP TO the challenge's target slot.
        // It can be earlier, in case the transaction was included before the based proposer's slot.
        if (verifiedHeader.Time > BeaconChainUtils._getTimestampFromSlot(challenge.signedCommitment.slot)) {
            // The block header timestamp is after the target slot, so the proposer didn't
            // honor the preconfirmation and the challenge is successful.
            // TODO: slash the based proposer
            _onChallengeSuccess(_challengeID);
            return;
        }

        bool isValid = _verifyInclusionProof(
            verifiedHeader.TxHash, _transactionIndex, _inclusionProof, challenge.signedCommitment.signedRawTransaction
        );

        if (!isValid) {
            // The challenge was successful: the proposer failed to honor the preconfirmation
            // TODO: slash the based proposer
            _onChallengeSuccess(_challengeID);
        } else {
            // The challenge was unsuccessful: the proposer honored the preconfirmation
            _onChallengeFailure(_challengeID);
        }
    }

    /// @notice Handle the success of a challenge
    /// @param _challengeID The unique ID of the challenge
    function _onChallengeSuccess(bytes32 _challengeID) internal {
        Challenge storage challenge = challenges[_challengeID];
        challenge.status = ChallengeStatus.Resolved;
        payable(challenge.challenger).transfer(CHALLENGE_BOND);
        emit ChallengeResolved(_challengeID, ChallengeResult.Success);
    }

    /// @notice Handle the failure of a challenge
    /// @param _challengeID The unique ID of the challenge
    function _onChallengeFailure(bytes32 _challengeID) internal {
        Challenge storage challenge = challenges[_challengeID];
        challenge.status = ChallengeStatus.Resolved;
        payable(challenge.basedProposer).transfer(CHALLENGE_BOND);
        emit ChallengeResolved(_challengeID, ChallengeResult.Failure);
    }

    /// @notice Fetch trustlessly valid block header data
    /// @param _proof The ABI-encoded proof of the block header
    /// @return header The block header data
    function _deriveBlockHeaderInfo(bytes calldata _proof) internal returns (CoreTypes.BlockHeaderData memory header) {
        // TODO: handle fee for proving. make payable?

        Fact memory fact = blockHeaderProver.prove(_proof, false);
        header = abi.decode(fact.data, (CoreTypes.BlockHeaderData));

        if (FactSignature.unwrap(fact.sig) != FactSignature.unwrap(FactSigs.blockHeaderSig(header.Number))) {
            revert UnexpectedFactSignature();
        }
    }

    /// @notice Fetch trustlessly valid account data at a given block number
    /// @param _proof The ABI-encoded proof of the account data
    /// @param _blockNumber The block number for which the account data is being proven
    /// @return account The account data
    function _deriveAccountData(bytes calldata _proof, uint256 _blockNumber)
        internal
        returns (CoreTypes.AccountData memory account)
    {
        // TODO: handle fee for proving. make payable?

        Fact memory fact = accountInfoProver.prove(_proof, false);
        account = abi.decode(fact.data, (CoreTypes.AccountData));

        // verify that the account data proof was provided for the correct block
        if (FactSignature.unwrap(fact.sig) != FactSignature.unwrap(FactSigs.accountFactSig(_blockNumber))) {
            revert UnexpectedFactSignature();
        }
    }

    /// @notice Verify the inclusion proof of a transaction in a block
    /// @param _transactionsRoot The transactions root of the block
    /// @param _transactionIndex The index of the transaction in the block
    /// @param _inclusionProof The Merkle proof of the transaction's inclusion in the block
    /// @param _signedRawTransaction The signed raw transaction being proven
    /// @return isValid true if the proof is valid, false otherwise
    function _verifyInclusionProof(
        bytes32 _transactionsRoot,
        uint256 _transactionIndex,
        bytes32[] calldata _inclusionProof,
        bytes memory _signedRawTransaction
    ) internal view returns (bool isValid) {
        // Check if the transactions root matches the signed commitment

        // The genelized index is the index of the merkle tree generated by the merkleization
        // process of a SSZ list of transactions. Since this list is dynamic and can be of maximum
        // length of 2^21 = 2_097_152, the merkleization process fills the tree with empty hashes,
        // therefore this number is an offset from where transactions hash tree root starts.
        // To read more, check out https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md#merkleization
        uint256 generalizedIndex = 2_097_152 + _transactionIndex;

        bytes32 leaf = SSZContainers._transactionHashTreeRoot(_signedRawTransaction);

        isValid = SSZ._verifyProof(_inclusionProof, _transactionsRoot, leaf, generalizedIndex);
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
            revert InvalidCommitmentSignature();
        }

        return signer;
    }

    /// @notice Hashes the inclusion commitment to a unique ID to index the challenge
    function _getCommitmentID(SignedCommitment memory _commitment) internal pure returns (bytes32) {
        return
            keccak256(abi.encodePacked(_commitment.slot, _commitment.transactionHash, _commitment.signedRawTransaction));
    }
}
