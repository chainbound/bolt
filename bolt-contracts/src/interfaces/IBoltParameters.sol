// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

interface IBoltParameters {
    function EPOCH_DURATION() external view returns (uint48);
    function SLASHING_WINDOW() external view returns (uint48);
    function ALLOW_UNSAFE_REGISTRATION() external view returns (bool);
    function MAX_CHALLENGE_DURATION() external view returns (uint48);
    function CHALLENGE_BOND() external view returns (uint256);
    function BLOCKHASH_EVM_LOOKBACK() external view returns (uint256);
    function JUSTIFICATION_DELAY() external view returns (uint256);
    function EIP4788_WINDOW() external view returns (uint256);
    function SLOT_TIME() external view returns (uint256);
    function ETH2_GENESIS_TIMESTAMP() external view returns (uint256);
    function BEACON_ROOTS_CONTRACT() external view returns (address);
    function MINIMUM_OPERATOR_STAKE() external view returns (uint256);
}
