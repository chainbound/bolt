// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Upgrades} from "@openzeppelin-foundry-upgrades/src/Upgrades.sol";

import {BoltParametersV1} from "../../../src/contracts/BoltParametersV1.sol";
import {BoltValidatorsV1} from "../../../src/contracts/BoltValidatorsV1.sol";
import {BoltManagerV1} from "../../../src/contracts/BoltManagerV1.sol";
import {BoltEigenLayerMiddlewareV1} from "../../../src/contracts/BoltEigenLayerMiddlewareV1.sol";
import {BoltSymbioticMiddlewareV1} from "../../../src/contracts/BoltSymbioticMiddlewareV1.sol";
import {BoltConfig} from "../../../src/lib/Config.sol";

contract UpgradeBolt is Script {
    function run() public {
        // TODO: Validate upgrades with Upgrades.validateUpgrade

        // TODO: Upgrade contracts with Upgrades.upgradeProxy
    }
}
