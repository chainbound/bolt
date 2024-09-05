// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {BoltValidators} from "../src/contracts/BoltValidators.sol";
import {BoltManager} from "../src/contracts/BoltManager.sol";

/// @notice Script to deploy the BoltManager and BoltValidators contracts.
contract DeployBoltManager is Script {
<<<<<<< HEAD
    function run(
        address symbioticNetwork,
        address symbioticOperatorRegistry,
        address symbioticOperatorNetOptIn,
        address symbioticVaultRegistry
    ) public {
        vm.startBroadcast();

        address sender = msg.sender;

        BoltValidators validators = new BoltValidators(sender);
        console.log("BoltValidators deployed at", address(validators));

        BoltManager manager = new BoltManager(
            address(sender),
            address(validators),
            symbioticNetwork,
            symbioticOperatorRegistry,
            symbioticOperatorNetOptIn,
            symbioticVaultRegistry,
            address(0),
            address(0)
        );
=======
    function run() public {
        vm.startBroadcast();

        address sender = msg.sender;

        BoltValidators validators = new BoltValidators(sender);
        console.log("BoltValidators deployed at", address(validators));

        address symbioticNetwork = address(0x1);

        BoltManager manager = new BoltManager(address(validators), symbioticNetwork);
>>>>>>> ca30ea2 (feat(registry): unsafe registration)
        console.log("BoltManager deployed at", address(manager));

        vm.stopBroadcast();
    }
}
