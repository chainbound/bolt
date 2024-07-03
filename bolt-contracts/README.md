# Bolt Contracts

## Registry
[`BoltRegistry.sol`](./src/contracts/BoltRegistry.sol) keeps track of registered proposers and operators. It allows an operator
to register by providing a list of validator indexes and depositing some collateral. It also exposes some view methods for off-chain actors to read.

### Registration

```js
function register(
    uint64[] calldata validatorIndexes,
    MetaData calldata metadata
) external payable;

```

The `MetaData` object holds information about the RPC and optionally some other information in `extra`:
```rs
struct MetaData {
    string rpc;
    bytes extra;
}
```

### Exiting
The exit process is a 2-step process. The first step is triggering the exit, which will put the registrant into an `EXITING` status after which the registrant should be considered inactive. After the `EXIT_COOLDOWN` of 1 day, the exit can be confirmed and the deposit will be returned. 

```js
function startExit() external;

function confirmExit(address payable recipient) external;
```

### View Methods
```js
function isActiveOperator(address _operator) external view returns (bool);

function getOperatorStatus(
    address _operator
) external view returns (Status);

function getOperatorForValidator(
    uint64 _validatorIndex
) external view returns (Registrant memory);
```

## Challenger
WIP

