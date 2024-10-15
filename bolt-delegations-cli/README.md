# Bolt Delegations CLI

`bolt-delegations-cli` is an offline command-line tool for safely generating delegation messages
signed with a BLS12-381 key for the [Constraints API](https://docs.boltprotocol.xyz/api/builder)
in [Bolt](https://docs.boltprotocol.xyz/).

The tool supports two key sources:

- Local: A BLS private key provided directly from a file.
- Keystore: A keystore file that contains an encrypted BLS private key.

Features:

- Offline usage: Safely generate delegation messages in an offline environment.
- Flexible key source: Support for both direct local BLS private keys and Ethereum keystore files (ERC-2335 format).
- BLS delegation signing: Sign delegation messages using a BLS secret key and output the signed delegation in JSON format.

## Usage

```bash
A CLI tool to generate signed delegation messages for BLS keys

Usage: bolt-delegations-cli <COMMAND>

Commands:
  generate  Generate delegation messages
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Example

1. Using a local BLS private key:

   ```shell
   bolt-delegations-cli generate \
       --delegatee-pubkey 0x7890ab... \
       --out my_delegations.json \
       --chain kurtosis \
       local \
       --secret-key 0xabc123... , 0xdef456..
   ```

2. Using an Ethereum keystore file:

   ```shell
   bolt-delegations-cli generate \
       --delegatee-pubkey 0x7890ab... \
       --out my_delegations.json \
       --chain kurtosis \
        keystore \
       --keystore-path /keys \
       --keystore-password myS3cr3tP@ssw0rd
   ```

### Supported Chains

The tool supports the following chains:

- `mainnet`
- `holesky`
- `helder`
- `kurtosis`

Each chain has its specific fork version used in computing the signing root.
