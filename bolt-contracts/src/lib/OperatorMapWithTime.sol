// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Checkpoints} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";

import {IBoltManagerV1} from "../interfaces/IBoltManagerV1.sol";
import {EnumerableMap} from "./EnumerableMap.sol";

library OperatorMapWithTime {
    using EnumerableMap for EnumerableMap.OperatorMap;

    error AlreadyAdded();
    error NotEnabled();
    error AlreadyEnabled();

    uint256 private constant ENABLED_TIME_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 private constant DISABLED_TIME_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFF << 48;

    function add(EnumerableMap.OperatorMap storage self, address addr) internal {
        if (!self.set(addr, IBoltManagerV1.Operator("", address(0), 0))) {
            revert AlreadyAdded();
        }
    }

    function disable(EnumerableMap.OperatorMap storage self, address addr) internal {
        IBoltManagerV1.Operator memory operator = self.get(addr);
        uint256 value = operator.timestamp;

        if (uint48(value) == 0 || uint48(value >> 48) != 0) {
            revert NotEnabled();
        }

        value |= uint256(Time.timestamp()) << 48;
        operator.timestamp = value;
        self.set(addr, operator);
    }

    function enable(EnumerableMap.OperatorMap storage self, address addr) internal {
        IBoltManagerV1.Operator memory operator = self.get(addr);
        uint256 value = operator.timestamp;

        if (uint48(value) != 0 && uint48(value >> 48) == 0) {
            revert AlreadyEnabled();
        }

        value = uint256(Time.timestamp());
        operator.timestamp = value;
        self.set(addr, operator);
    }

    function atWithTimes(
        EnumerableMap.OperatorMap storage self,
        uint256 idx
    ) internal view returns (address key, uint48 enabledTime, uint48 disabledTime) {
        IBoltManagerV1.Operator memory value;
        (key, value) = self.at(idx);
        uint256 timestamp = value.timestamp;
        enabledTime = uint48(timestamp);
        disabledTime = uint48(timestamp >> 48);
    }

    function getTimes(
        EnumerableMap.OperatorMap storage self,
        address addr
    ) internal view returns (uint48 enabledTime, uint48 disabledTime) {
        IBoltManagerV1.Operator memory value = self.get(addr);
        enabledTime = uint48(value.timestamp);
        disabledTime = uint48(value.timestamp >> 48);
    }
}
