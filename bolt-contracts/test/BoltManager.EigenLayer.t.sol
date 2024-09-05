// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console} from "forge-std/Test.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";

import {AVSDirectoryStorage} from "@eigenlayer/src/contracts/core/AVSDirectoryStorage.sol";
import {DelegationManagerStorage} from "@eigenlayer/src/contracts/core/DelegationManagerStorage.sol";

contract BoltManagerEigenLayerTest is Test {
    uint48 public constant EPOCH_DURATION = 1 days;

    BoltValidators public validators;
    BoltManager public manager;

    uint64[] public validatorIndexes;

    address deployer = makeAddr("deployer");
    address admin = makeAddr("admin");
    address provider = makeAddr("provider");
    address operator = makeAddr("operator");
    address validator = makeAddr("validator");
    address networkAdmin = makeAddr("networkAdmin");
    address vaultAdmin = makeAddr("vaultAdmin");

    // TODO: Deploy a real Symbiotic collateral contract
    address collateral = makeAddr("collateral");

    function setUp() public {
        // Deploy Bolt contracts
        validators = new BoltValidators(admin);
        manager = new BoltManager(
            address(validators),
            networkAdmin,
            address(0),
            address(0),
            address(0),
            address(0),
            address(0)
        );
    }
}
