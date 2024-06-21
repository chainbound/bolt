EXECUTION_RPC=$(kurtosis port print bolt-devnet el-1-geth-lighthouse rpc)
echo "RPC endpoint: $EXECUTION_RPC"

# Beacon api endpoint
BEACON_RPC=$(kurtosis port print bolt-devnet cl-1-lighthouse-geth http)
echo "Beacon RPC endpoint: $BEACON_RPC"

# Bolt Sidecar URL
BOLT_SIDECAR="http://$(kurtosis port print bolt-devnet mev-sidecar-api-0 api)"
echo "Bolt Sidecar URL: $BOLT_SIDECAR"

PRECONF_CLIENT_CONFIG_FILE=config.toml
TITAN_GATEWAY_URL=http://TODO:8080

# Update the preconf client config file to use the devnet URLs
(
        cd ./preconf-client || exit
        sed -i "s|\$BEACON_API|$BEACON_RPC|g" "$PRECONF_CLIENT_CONFIG_FILE"
        sed -i "s|\$EXECUTION_API|$EXECUTION_RPC|g" "$PRECONF_CLIENT_CONFIG_FILE"
        sed -i "s|\$BOLT_ENDPOINT|$BOLT_SIDECAR|g" "$PRECONF_CLIENT_CONFIG_FILE"
        sed -i "s|\$TITAN_GATEWAY|$TITAN_GATEWAY_URL|g" "$PRECONF_CLIENT_CONFIG_FILE"
)
