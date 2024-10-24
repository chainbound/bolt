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

## Verifying Storage Layout
You can verify storage layouts using `forge inspect`. Example:

```bash
forge inspect BoltSymbioticMiddlewareV2 storage-layout --pretty
```

This will output the following table:
| Name                   | Type                                  | Slot | Offset | Bytes | Contract                                                              |
|------------------------|---------------------------------------|------|--------|-------|-----------------------------------------------------------------------|
| INSTANT_SLASHER_TYPE   | uint256                               | 0    | 0      | 32    | src/contracts/BoltSymbioticMiddlewareV2.sol:BoltSymbioticMiddlewareV2 |
| VETO_SLASHER_TYPE      | uint256                               | 1    | 0      | 32    | src/contracts/BoltSymbioticMiddlewareV2.sol:BoltSymbioticMiddlewareV2 |
| START_TIMESTAMP        | uint48                                | 2    | 0      | 6     | src/contracts/BoltSymbioticMiddlewareV2.sol:BoltSymbioticMiddlewareV2 |
| parameters             | contract IBoltParametersV1            | 2    | 6      | 20    | src/contracts/BoltSymbioticMiddlewareV2.sol:BoltSymbioticMiddlewareV2 |
| manager                | contract IBoltManagerV1               | 3    | 0      | 20    | src/contracts/BoltSymbioticMiddlewareV2.sol:BoltSymbioticMiddlewareV2 |
| vaults                 | struct EnumerableMap.AddressToUintMap | 4    | 0      | 96    | src/contracts/BoltSymbioticMiddlewareV2.sol:BoltSymbioticMiddlewareV2 |
| BOLT_SYMBIOTIC_NETWORK | address                               | 7    | 0      | 20    | src/contracts/BoltSymbioticMiddlewareV2.sol:BoltSymbioticMiddlewareV2 |
| OPERATOR_REGISTRY      | address                               | 8    | 0      | 20    | src/contracts/BoltSymbioticMiddlewareV2.sol:BoltSymbioticMiddlewareV2 |
| VAULT_FACTORY          | address                               | 9    | 0      | 20    | src/contracts/BoltSymbioticMiddlewareV2.sol:BoltSymbioticMiddlewareV2 |
| OPERATOR_NET_OPTIN     | address                               | 10   | 0      | 20    | src/contracts/BoltSymbioticMiddlewareV2.sol:BoltSymbioticMiddlewareV2 |
| NAME_HASH              | bytes32                               | 11   | 0      | 32    | src/contracts/BoltSymbioticMiddlewareV2.sol:BoltSymbioticMiddlewareV2 |
| __gap                  | uint256[38]                           | 12   | 0      | 1216  | src/contracts/BoltSymbioticMiddlewareV2.sol:BoltSymbioticMiddlewareV2 |

The last line indicating the `__gap` storage slot is what's most important. `__gap` has a total of 50 storage slots reserved. You **MUST** verify that the array length of __gap`, in this case `38`, is equal to `50 - __gap.Slot`. In this case, the `Slot` column for `__gap` shows 12, so the layout is correct.

## Reinitializers
In case you need to reinitialize your contract, you'll need to create a reinitializer.

Let `x` = your version number. Add the following new initializer to the contract to be upgraded:

```solidity
function initializeVx() public reinitializer(x) { ... }
```

For more info, check out https://docs.openzeppelin.com/contracts/5.x/api/proxy#Initializable.