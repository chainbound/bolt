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

## Unsafe
In order to run an unsafe upgrade, set `Options.unsafeSkipAllChecks` to `true`:
```solidity
Options memory opts;
opts.unsafeSkipAllChecks = true;
```

## Reinitializers
In case you need to reinitialize your contract, you'll need to create a reinitializer.

Let `x` = your version number. Add the following new initializer to the contract to be upgraded:

```solidity
function initializeVx() public reinitializer(x) { ... }
```

For more info, check out https://docs.openzeppelin.com/contracts/5.x/api/proxy#Initializable.