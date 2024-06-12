#!/bin/bash

echo "Starting the devnet..."

# spin up the kurtosis devnet
kurtosis run --enclave bolt-devnet github.com/chainbound/ethereum-package@infra/zuberlin-devnet --args-file ./scripts/kurtosis_config.yaml
echo "Devnet online! Waiting for the RPC to be available..."
sleep 5

EXECUTION_RPC=$(kurtosis port print bolt-devnet el-1-geth-lighthouse rpc)
PK="bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31"
echo "RPC endpoint: $EXECUTION_RPC"

# wait for the rpc to be available
while ! curl -s -X POST --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' "$EXECUTION_RPC" >/dev/null; do
	sleep 1
done

# Beacon api endpoint
BEACON_RPC=$(kurtosis port print bolt-devnet cl-1-lighthouse-geth http)
echo "Beacon RPC endpoint: $BEACON_RPC"

# Bolt Sidecar URL
BOLT_SIDECAR="http://$(kurtosis port print bolt-devnet mev-sidecar-api api)"
echo "Bolt Sidecar URL: $BOLT_SIDECAR"

SPAMMER_CONFIG_FILE=config.toml
TITAN_GATEWAY_URL=http://TODO:8080

# Update the spammer config file to use the devnet URLs
(
	cd ./bolt-spammer || exit
	sed -i "s|\$BEACON_API|$BEACON_RPC|g" "$SPAMMER_CONFIG_FILE"
	sed -i "s|\$EXECUTION_API|$EXECUTION_RPC|g" "$SPAMMER_CONFIG_FILE"
	sed -i "s|\$BOLT_ENDPOINT|$BOLT_SIDECAR|g" "$SPAMMER_CONFIG_FILE"
	sed -i "s|\$TITAN_GATEWAY|$TITAN_GATEWAY_URL|g" "$SPAMMER_CONFIG_FILE"
)

# deploy the contracts
(
	cd ./bolt-contracts || exit
	forge build # make sure the contracts are compiled before deploying
	forge script script/DeployOnDevnet.s.sol --broadcast --rpc-url "$EXECUTION_RPC" --private-key "$PK"
)
echo "Contracts deployed!"
