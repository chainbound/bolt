// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {EnumerableSet} from "lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import {IBoltManager} from "../interfaces/IBoltManager.sol";

library EnumerableMap {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    error KeyNotFound();

    struct OperatorMap {
        // Storage of keys
        EnumerableSet.Bytes32Set _keys;
        mapping(bytes32 key => IBoltManager.Operator) _values;
    }

    function set(OperatorMap storage self, address key, IBoltManager.Operator memory value) internal returns (bool) {
        bytes32 keyBytes = bytes32(uint256(uint160(key)));
        self._values[keyBytes] = value;
        return self._keys.add(keyBytes);
    }

    function remove(OperatorMap storage self, address key) internal returns (bool) {
        bytes32 keyBytes = bytes32(uint256(uint160(key)));
        delete self._values[keyBytes];
        return self._keys.remove(keyBytes);
    }

    function contains(OperatorMap storage self, address key) internal view returns (bool) {
        return self._keys.contains(bytes32(uint256(uint160(key))));
    }

    function length(
        OperatorMap storage self
    ) internal view returns (uint256) {
        return self._keys.length();
    }

    function at(
        OperatorMap storage self,
        uint256 index
    ) internal view returns (address, IBoltManager.Operator memory) {
        bytes32 key = self._keys.at(index);
        return (address(uint160(uint256(key))), self._values[key]);
    }

    function get(OperatorMap storage self, address key) internal view returns (IBoltManager.Operator memory) {
        if (!contains(self, key)) {
            revert KeyNotFound();
        }

        return self._values[bytes32(uint256(uint160(key)))];
    }

    function keys(
        OperatorMap storage self
    ) internal view returns (address[] memory) {
        address[] memory result = new address[](self._keys.length());
        for (uint256 i = 0; i < self._keys.length(); i++) {
            result[i] = address(uint160(uint256(self._keys.at(i))));
        }

        return result;
    }
}
