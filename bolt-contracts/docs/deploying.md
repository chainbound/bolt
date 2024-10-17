# Deploying

**This should only be done once with the `V1` contracts. For upgrades, refer to the [upgrading doc](./upgrading.md).**

## Configuration

There are 2 JSON configuration files:
- [`config/holesky/deployments.json`](../config/holesky/deployments.json): contains deployment addresses of EigenLayer ([here](https://github.com/Layr-Labs/eigenlayer-contracts/blob/dev/README.md#deployments)) and Symbiotic ([here](https://docs.symbiotic.fi/deployments)). 
- [`config/holesky/parameters.json`](../config/holesky/parameters.json): contains the launch parameters for `BoltParameters`.



## Deployment Guide
Make sure we have a full compilation for the Foundry Upgrades Toolkit:
```bash
forge clean && forge build
```

And have a local Anvil fork running to test and validate deployments:

```bash
anvil --fork-url $HOLESKY_RPC
```

> [!IMPORTANT]  
> Run everything on the local Anvil fork first! This requires just replacing the $HOLESKY_RPC with the $ANVIL_RPC.

### Pre-deployment

Register a Symbiotic network for Bolt with the Symbiotic `NetworkRegistry`. The private key with which the script is run will determine the network address. This private key will also need to be used later.

```bash
forge script script/holesky/SymbioticSetup.s.sol $HOLESKY_RPC --private-key $NETWORK_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" registerNetwork
```

### Deployment

Run the following script to deploy Bolt V1:
```bash
forge script script/holesky/Deploy.s.sol --rpc-url $HOLESKY_RPC --private-key $PRIVATE_KEY --broadcast -vvvv
```

This will deploy all the contracts. Now update `deployments.json` with the Symbiotic middleware, because we'll need to register it
in the next step.

### Post-deployment

Register the deployed `SymbioticMiddleware` with the Symbiotic `NetworkMiddlewareService`. IMPORTANT: this script needs
to be run with the network private key!

```bash
forge script script/holesky/SymbioticSetup.s.sol $HOLESKY_RPC --private-key $NETWORK_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" registerMiddleware
```