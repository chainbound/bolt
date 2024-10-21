# Upgrading Guide

When upgrading contracts, always keep the old implementation of the contracts around and increment the version number.
For example, when upgrading `BoltManagerV1`, copy it into a new file called `BoltManagerV2` and make your changes.

This is needed to reference check the new contracts with the old contracts so that the OpenZeppelin Upgrades library can
validate the safety of the upgrade. You MUST add this reference when upgrading a contract:

```solidity
Options memory opts;
opts.referenceContract = "BoltManagerV1.sol";
bytes memory initManager = abi.encodeCall(BoltManagerV2.initialize, (params));
Upgrades.upgradeProxy(proxy, "BoltManagerV2.sol", initManager, opts);
```

Before an upgrade, update the [`Upgrade.s.sol`](../script/holesky/Upgrade.s.sol) script to include the correct contracts, references and configurations.