# Bolt CLI client

This is a simple CLI tool to interact with Bolt.

## Requirements

- [Rust toolchain & Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed
- A wallet with some funds to send transactions

## How to use

Bolt Client offers different ways to send commitment requests. Here's how to use them:

### Use the default Bolt RPC

For regular usage, you can use the default Bolt RPC server to automatically fetch the
lookahead data from the beacon chain and send the transaction to the next Bolt sidecar in line.

To do this, prepare the environment variables (either in a `.env` file, or as CLI arguments):

- `BOLT_PRIVATE_KEY` or `--private-key`: the private key of the account to send transactions from
- `--blob`: bool flag to send a blob-carrying transaction (default: false)
- `--count`: the number of transactions to send in a single request (default: 1)

Run the CLI tool:

```shell
 cargo run
```

### Use your own beacon node and registry contract

If you don't want to use the default RPC server, you can send transactions manually.
To do this, you need to provide the following environment variables (either in a `.env` file, or as CLI arguments):

- `--use-registry`: bool flag to fetch data from a local node instead of the RPC_URL (default: false)
- `BOLT_RPC_URL` or `--rpc-url`: the URL of an execution client (e.g. Geth)'s RPC server (default: Chainbound's RPC)
- `BOLT_NONCE_OFFSET` or `--nonce-offset`: the offset to add to the account's nonce (default: 0)
- `BOLT_REGISTRY_ADDRESS` or `--registry-address`: the address of the bolt-registry smart contract
- `BOLT_BEACON_CLIENT_URL` or `--beacon-client-url`: the URL of the beacon client's HTTP server

Run the CLI tool with the desired command and arguments, if any.

```shell
 cargo run -- [options]
```
