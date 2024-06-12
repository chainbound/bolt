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

# deploy the contracts
(
	cd ./bolt-contracts || exit
	forge build # make sure the contracts are compiled before deploying
	forge script script/DeployOnDevnet.s.sol --broadcast --rpc-url "$EXECUTION_RPC" --private-key "$PK"
)
echo "Contracts deployed!"

# setup the preconf client config
exec ./scripts/preconf-client-config.sh
