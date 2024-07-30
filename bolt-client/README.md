# Bolt CLI client

This is a simple CLI tool to interact with Bolt.

## Requirements

- Rust toolchain & Cargo

## How to use

1. Prepare the environment variables (either in a `.env` file, or as CLI arguments):

   - `BOLT_RPC_URL` or `--rpc-url`: the URL of the Bolt RPC server (default: Chainbound's RPC)
   - `BOLT_PRIVATE_KEY` or `--private-key`: the private key of the account to send transactions from
   - `BOLT_NONCE_OFFSET` or `--nonce-offset`: the offset to add to the account's nonce (default: 0)
   - `--blob`: bool flag to send a blob-carrying transaction (default: false)

**Optionally**, you can use the following flags to fetch the lookahead data from the beacon chain directly
instead of relying on the RPC server:

- `--use-registry`: bool flag to fetch data from a local node instead of the RPC_URL (default: false)
- `BOLT_REGISTRY_ADDRESS` or `--registry-address`: the address of the bolt-registry smart contract
- `BOLT_BEACON_CLIENT_URL` or `--beacon-client-url`: the URL of the CL node to use

1. Run the CLI tool with the desired command and arguments, if any.

   ```shell
    cargo run -- [options]
   ```
