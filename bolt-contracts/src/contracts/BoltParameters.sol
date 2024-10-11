// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

contract BoltParameters is OwnableUpgradeable, UUPSUpgradeable {
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

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     * This can be validated with the Openzeppelin Foundry Upgrades toolkit.
     *
     * Total storage slots: 50
     */
    uint256[49] private __gap;

    // ============== PROXY METHODS ============== //

    /// @notice The initializer for the BoltManager contract.
    /// @param _epochDuration The epoch duration.
    function initialize(
        address _owner,
        uint48 _epochDuration,
        uint48 _slashingWindow,
        bool _allowUnsafeRegistration
    ) public initializer {
        __Ownable_init(_owner);

        EPOCH_DURATION = _epochDuration;
        SLASHING_WINDOW = _slashingWindow;
        ALLOW_UNSAFE_REGISTRATION = _allowUnsafeRegistration;
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
