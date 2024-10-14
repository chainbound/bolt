// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

library BeaconChainUtils {
    /// @notice The address of the BeaconRoots contract
    /// @dev See EIP-4788 for more info
    address internal constant BEACON_ROOTS_CONTRACT = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @notice The EIP-4788 time window in slot
    uint256 internal constant EIP4788_WINDOW = 8191;

    /// @notice The duration of a slot in seconds
    uint256 internal constant SLOT_TIME = 12;

    /// @notice The number of slots to wait before considering a block justified by LMD-GHOST.
    uint256 internal constant JUSTIFICATION_DELAY_SLOTS = 32;

    /// @notice The timestamp of the genesis of the eth2 chain
    uint256 internal constant ETH2_GENESIS_TIMESTAMP = 1_606_824_023;

    /// @notice Error emitted when a beacon block root is not found
    error BeaconRootNotFound();

    /// @notice Get the slot number from a given timestamp
    /// @param _timestamp The timestamp
    /// @return The slot number
    function _getSlotFromTimestamp(
        uint256 _timestamp
    ) internal pure returns (uint256) {
        return (_timestamp - ETH2_GENESIS_TIMESTAMP) / SLOT_TIME;
    }

    /// @notice Get the timestamp from a given slot
    /// @param _slot The slot number
    /// @return The timestamp
    function _getTimestampFromSlot(
        uint256 _slot
    ) internal pure returns (uint256) {
        return ETH2_GENESIS_TIMESTAMP + _slot * SLOT_TIME;
    }

    /// @notice Get the beacon block root for a given slot
    /// @param _slot The slot number
    /// @return The beacon block root
    function _getBeaconBlockRootAtSlot(
        uint256 _slot
    ) internal view returns (bytes32) {
        uint256 slotTimestamp = ETH2_GENESIS_TIMESTAMP + _slot * SLOT_TIME;
        return _getBeaconBlockRootAtTimestamp(slotTimestamp);
    }

    function _getBeaconBlockRootAtTimestamp(
        uint256 _timestamp
    ) internal view returns (bytes32) {
        (bool success, bytes memory data) = BEACON_ROOTS_CONTRACT.staticcall(abi.encode(_timestamp));

        if (!success || data.length == 0) {
            revert BeaconRootNotFound();
        }

        return abi.decode(data, (bytes32));
    }

    /// @notice Get the latest beacon block root
    /// @return The beacon block root
    function _getLatestBeaconBlockRoot() internal view returns (bytes32) {
        uint256 latestSlot = _getSlotFromTimestamp(block.timestamp);
        return _getBeaconBlockRootAtSlot(latestSlot);
    }

    /// @notice Get the current slot
    /// @return The current slot
    function _getCurrentSlot() internal view returns (uint256) {
        return _getSlotFromTimestamp(block.timestamp);
    }

    /// @notice Check if a timestamp is within the EIP-4788 window
    /// @param _timestamp The timestamp
    /// @return True if the timestamp is within the EIP-4788 window, false otherwise
    function _isWithinEIP4788Window(
        uint256 _timestamp
    ) internal view returns (bool) {
        return _getSlotFromTimestamp(_timestamp) <= _getCurrentSlot() + EIP4788_WINDOW;
    }
}
