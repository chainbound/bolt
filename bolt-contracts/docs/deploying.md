# Deploying

**This should only be done once with the `V1` contracts. For upgrades, refer to the [upgrading doc](./upgrading.md).**

## Configuration

There are 2 JSON configuration files:
- [`config/holesky/deployments.json`](../config/holesky/deployments.json): contains deployment addresses of EigenLayer ([here](https://github.com/Layr-Labs/eigenlayer-contracts/blob/dev/README.md#deployments)) and Symbiotic ([here](https://docs.symbiotic.fi/deployments)). 
- [`config/holesky/parameters.json`](../config/holesky/parameters.json): contains the launch parameters for `BoltParameters`.


## Deploy Script
Make sure we have a full compilation for the Foundry Upgrades Toolkit:
```bash
forge clean && forge build
```

Run the following script to test deployment on an Anvil fork:
```bash
anvil --fork-url $HOLESKY_RPC
forge script script/holesky/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --private-key $PRIVATE_KEY --broadcast -vvvv
```

Run the following script to deploy Bolt V1:
```bash
forge script script/holesky/Deploy.s.sol --rpc-url $HOLESKY_RPC --private-key $PRIVATE_KEY --broadcast -vvvv
```
