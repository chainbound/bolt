# Deployment Guide

**This should only be done once with the `V1` contracts. For upgrades, refer to the [upgrading doc](./upgrading.md).**

## Configuration

There are 2 JSON configuration files:
- [`config/holesky/deployments.json`](../../config/holesky/deployments.json): contains deployment addresses of EigenLayer ([here](https://github.com/Layr-Labs/eigenlayer-contracts/blob/dev/README.md#deployments)) and Symbiotic ([here](https://docs.symbiotic.fi/deployments)). 
- [`config/holesky/parameters.json`](../../config/holesky/parameters.json): contains the launch parameters for `BoltParameters`.



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

Also set your private keys as environment variables:

```bash
export NETWORK_PRIVATE_KEY=0x...
export ADMIN_PRIVATE_KEY=0x...
```

### Pre-deployment

- Register a Symbiotic network for Bolt with the Symbiotic `NetworkRegistry`. The private key with which the script is run will determine the network address. This private key will also need to be used later.

```bash
forge script script/holesky/admin/helpers/Symbiotic.s.sol --rpc-url $HOLESKY_RPC --private-key $NETWORK_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" registerNetwork
```

Make sure [`deployments.json`](../../config/holesky/deployments.json) contains the correct address for the Symbiotic network.

- Deploy Bolt-specific Symbiotic Vaults. Vaults will be deployed from the [`vaults.json`](../../config/holesky/vaults.json) configuration file.

```bash
forge script script/holesky/admin/helpers/DeployVaults.s.sol --rpc-url $HOLESKY_RPC --private-key $ADMIN_PRIVATE_KEY --verify --broadcast -vvvv
```

If vaults with the `(collateral, admin)` combination already exist, they won't be recreated. After these vaults have been created, copy their
addresses into the [`deployments.json`](../../config/holesky/deployments.json) file under `symbiotic.supportedVaults`.

### Deployment

Run the following script to deploy Bolt V1:
```bash
forge script script/holesky/admin/Deploy.s.sol --rpc-url $HOLESKY_RPC --private-key $ADMIN_PRIVATE_KEY --verify --broadcast -vvvv
```

This will deploy all the contracts. The address corresponding to the private key will be the system admin.

Now update `deployments.json` with the Symbiotic and EigenLayer middleware contracts, because we'll need to register it in the next step. Also update the `bolt` section with the correct addresses.

### Post-deployment

Register the deployed `SymbioticMiddleware` with the Symbiotic `NetworkMiddlewareService`. IMPORTANT: this script needs
to be run with the network private key!

```bash
forge script script/holesky/admin/helpers/Symbiotic.s.sol --rpc-url $HOLESKY_RPC --private-key $NETWORK_PRIVATE_KEY --broadcast -vvvv --sig "run(string memory arg)" registerMiddleware
```

Also set the AVS metadata in the EigenLayer AVS Directory, needs to be run with the **admin private key** used at deployment.

```bash
forge script script/holesky/admin/helpers/RegisterAVS.s.sol --rpc-url $HOLESKY_RPC --private-key $ADMIN_PRIVATE_KEY --broadcast -vvvv 
```

> [!IMPORTANT]
> After the `deployments.json` file has been fully updated with the correct contract addresses, push it to Github.


### Other Scripts

#### Modifying supported Symbiotic Vaults
This script will update supported vaults according to `deployments.json`, and remove any vaults that have been whitelisted but are no longer in the `symbiotic.supportedVaults` list.
```bash
forge script script/holesky/admin/helpers/UpdateSupportedVaults.s.sol --rpc-url $HOLESKY_RPC --private-key $ADMIN_PRIVATE_KEY --broadcast -vvv
```