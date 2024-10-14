// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title Bolt Parameters
/// @notice The BoltParameters contract contains all the parameters for the Bolt protocol.
/// @dev This contract is upgradeable using the UUPSProxy pattern. Storage layout remains fixed across upgrades
/// with the use of storage gaps.
/// See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
contract BoltParameters is OwnableUpgradeable, UUPSUpgradeable {
    // =========== STORAGE =========== //

    // --> Storage layout marker: 0 bits

    /// @notice Duration of an epoch in seconds.
    uint48 public EPOCH_DURATION;

    /// @notice Duration of the slashing window in seconds.
    uint48 public SLASHING_WINDOW;

    /// @notice Whether to allow unsafe registration of validators
    /// @dev Until the BLS12_381 precompile is live, we need to allow unsafe registration
    /// which means we don't check the BLS signature of the validator pubkey.
    bool public ALLOW_UNSAFE_REGISTRATION;
    // --> Storage layout marker: 48 + 48 + 8 = 104 bits

    /// @notice The maximum duration of a challenge before it is automatically considered valid.
    uint48 public MAX_CHALLENGE_DURATION;

    /// @notice The challenge bond required to open a challenge.
    uint256 public CHALLENGE_BOND;

    /// @notice The maximum number of blocks to look back for block hashes in the EVM.
    uint256 public BLOCKHASH_EVM_LOOKBACK;
    // --> Storage layout marker: 3 words

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     * This can be validated with the Openzeppelin Foundry Upgrades toolkit.
     *
     * Total storage slots: 50
     */
    uint256[47] private __gap;

    // ============== INITIALIZER ============== //

    /// @notice The initializer for the BoltManager contract.
    /// @param _epochDuration The epoch duration.
    function initialize(
        address _owner,
        uint48 _epochDuration,
        uint48 _slashingWindow,
        uint48 _maxChallengeDuration,
        bool _allowUnsafeRegistration,
        uint256 _challengeBond,
        uint256 _blockhashEvmLookback
    ) public initializer {
        __Ownable_init(_owner);

        EPOCH_DURATION = _epochDuration;
        SLASHING_WINDOW = _slashingWindow;
        ALLOW_UNSAFE_REGISTRATION = _allowUnsafeRegistration;
        MAX_CHALLENGE_DURATION = _maxChallengeDuration;
        CHALLENGE_BOND = _challengeBond;
        BLOCKHASH_EVM_LOOKBACK = _blockhashEvmLookback;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // ========= ADMIN METHODS ========= //

    /// @notice Enable or disable the use of the BLS precompile
    /// @param allowUnsafeRegistration Whether to allow unsafe registration of validators
    function setAllowUnsafeRegistration(
        bool allowUnsafeRegistration
    ) public onlyOwner {
        ALLOW_UNSAFE_REGISTRATION = allowUnsafeRegistration;
    }
}
