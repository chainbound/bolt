// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

library BeaconChainUtils {
    /// @notice The address of the BeaconRoots contract
    /// @dev See EIP-4788 for more info
    address internal constant BEACON_ROOTS_CONTRACT = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02;

    /// @notice The duration of a slot in seconds
    uint256 internal constant SLOT_TIME = 12;

    /// @notice The timestamp of the genesis of the eth2 chain
    uint256 internal constant ETH2_GENESIS_TIMESTAMP = 1606824023;

    /// @notice Error emitted when a beacon block root is not found
    error BeaconRootNotFound();

    /// @notice Get the slot number from a given timestamp
    /// @param _timestamp The timestamp
    /// @return The slot number
    function _getSlotFromTimestamp(uint256 _timestamp) internal pure returns (uint256) {
        return (_timestamp - ETH2_GENESIS_TIMESTAMP) / SLOT_TIME;
    }

    /// @notice Get the timestamp from a given slot
    /// @param _slot The slot number
    /// @return The timestamp
    function _getTimestampFromSlot(uint256 _slot) internal pure returns (uint256) {
        return ETH2_GENESIS_TIMESTAMP + _slot * SLOT_TIME;
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
