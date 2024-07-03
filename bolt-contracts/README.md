# Bolt Contracts

## Registry
[`BoltRegistry.sol`](./src/contracts/BoltRegistry.sol) keeps track of registered proposers and operators. It allows an operator
to register by providing a list of validator indexes and depositing some collateral. It also exposes some view methods for off-chain actors to read.

### Registration

```js
function register(
    uint64[] calldata validatorIndexes,
    string calldata rpc,
    bytes calldata extra
) external payable;

```
Besides validatorIndexes, `register` also registers an RPC endpoint and some optional other information in `extra`.

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

## Deploying
```bash
# Example for Helder devnet. Set PRIVATE_KEY to your hex-encoded private key.
PRIVATE_KEY=$PRIVATE_KEY forge script script/DeployRegistry.s.sol --rpc-url https://rpc.helder-devnets.xyz --broadcast --legacy
```

## Registering
```bash
# Example for Helder devnet. Set PRIVATE_KEY to your hex-encoded private key.
export PRIVATE_KEY="0x..."
export RPC_ADDR="http://test.com"
export VALIDATOR_INDEXES="1,2,3,4"
forge script script/RegisterValidators.s.sol --rpc-url https://rpc.helder-devnets.xyz --broadcast --legacy
```

## Deployments
| Contract | Network | Address |
| -------- | ------- | ------- |
| `BoltRegistry.sol` | Helder (7014190335) | 0xdF11D829eeC4C192774F3Ec171D822f6Cb4C14d9 |