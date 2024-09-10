// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../script/RegisterValidators.s.sol";

contract StringToUintArrayTest is Test {
    function setUp() public {}

    function testParseValidatorIndexes1() public pure {
        uint256[] memory indexes = StringToUintArrayLib.fromStr("1,2,3,4");
        uint256[4] memory expected;
        expected[0] = 1;
        expected[1] = 2;
        expected[2] = 3;
        expected[3] = 4;

        assertEq(indexes.length, expected.length);
        for (uint256 i = 0; i < indexes.length; i++) {
            assertEq(indexes[i], expected[i]);
        }
    }

    function testParseValidatorIndexes2() public pure {
        uint256[] memory indexes = StringToUintArrayLib.fromStr("1..4");
        uint256[4] memory expected;
        expected[0] = 1;
        expected[1] = 2;
        expected[2] = 3;
        expected[3] = 4;

        assertEq(indexes.length, expected.length);
        for (uint256 i = 0; i < indexes.length; i++) {
            assertEq(indexes[i], expected[i]);
        }
    }

    function testParseValidatorIndexes3() public pure {
        uint256[] memory indexes = StringToUintArrayLib.fromStr("1..4,6..8");
        uint256[7] memory expected;
        expected[0] = 1;
        expected[1] = 2;
        expected[2] = 3;
        expected[3] = 4;
        expected[4] = 6;
        expected[5] = 7;
        expected[6] = 8;

        assertEq(indexes.length, expected.length);
        for (uint256 i = 0; i < indexes.length; i++) {
            assertEq(indexes[i], expected[i]);
        }
    }

    function testParseValidatorIndexes4() public pure {
        uint256[] memory indexes = StringToUintArrayLib.fromStr("1,2..4,6..8");
        uint256[7] memory expected;
        expected[0] = 1;
        expected[1] = 2;
        expected[2] = 3;
        expected[3] = 4;
        expected[4] = 6;
        expected[5] = 7;
        expected[6] = 8;

        assertEq(indexes.length, expected.length);
        for (uint256 i = 0; i < indexes.length; i++) {
            assertEq(indexes[i], expected[i]);
        }
    }

    function testParse100Indexes() public pure {
        string memory input = "1..100";

        uint256[] memory indexes = StringToUintArrayLib.fromStr(input);
        assertEq(indexes.length, 100);
        for (uint256 i = 0; i < indexes.length; i++) {
            assertEq(indexes[i], i + 1);
        }
    }
}
