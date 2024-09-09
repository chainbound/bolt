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

    address admin = makeAddr("admin");

    function setUp() public {
        // Deploy EigenLayer contracts
        EigenLayerDeployer eigenLayerDeployer = new EigenLayerDeployer();

        // Deploy Bolt contracts
        validators = new BoltValidators(admin);
        manager = new BoltManager(
            address(validators),
            networkAdmin,
            address(0),
            address(0),
            address(0),
            address(0),
            address(eigenLayerDeployer.avsDirectory()),
            address(eigenLayerDeployer.delegationManager())
        );

        console.logAddress(address(eigenLayerDeployer.strategyManager()));
    }
}
