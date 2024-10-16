# Deploying

**This should only be done once with the `V1` contracts. For upgrades, refer to the [upgrading doc](./upgrading.md).**

Run the following script to test deployment on an Anvil fork:
```bash
anvil --fork-url $HOLESKY_RPC
forge script script/holesky/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --private-key $PRIVATE_KEY --broadcast -vvvv
```

Run the following script to deploy Bolt V1:
```bash
forge script script/holesky/Deploy.s.sol --rpc-url $HOLESKY_RPC --private-key $PRIVATE_KEY --broadcast -vvvv
```