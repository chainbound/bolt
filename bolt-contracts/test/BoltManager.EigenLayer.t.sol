// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";

import {AVSDirectoryStorage} from "@eigenlayer/src/contracts/core/AVSDirectoryStorage.sol";
import {DelegationManagerStorage} from "@eigenlayer/src/contracts/core/DelegationManagerStorage.sol";
import {EigenLayerDeployer} from "../test/fixtures/EigenLayerDeplyer.f.sol";

contract BoltManagerEigenLayerTest is Test {
    BoltValidators public validators;
    BoltManager public manager;
    EigenLayerDeployer public eigenLayerDeployer;

    address public staker = makeAddr("staker");

    address admin = makeAddr("admin");

    function setUp() public {
        // Deploy EigenLayer contracts
        eigenLayerDeployer = new EigenLayerDeployer(staker);
        eigenLayerDeployer.setUp();

        // Deploy Bolt contracts
        validators = new BoltValidators(admin);
        manager = new BoltManager(
            address(validators),
            address(0),
            address(0),
            address(0),
            address(0),
            address(0),
            address(eigenLayerDeployer.avsDirectory()),
            address(eigenLayerDeployer.delegationManager())
        );
    }

    function test_just_deployed() public {}
}
