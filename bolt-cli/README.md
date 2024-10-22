# Bolt CLI

Components:

- `bolt-delegations-cli`: A command-line tool for generating delegation messages signed with a BLS12-381 key.

## Bolt-delegations-cli

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

### Usage

```text
A CLI tool to generate signed delegation messages for BLS keys

Usage: bolt-delegations-cli <COMMAND>

Commands:
  generate  Generate delegation messages
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

#### Example

1. Using a local BLS private key:

   ```text
   bolt-delegations-cli generate \
       --delegatee-pubkey 0x7890ab... \
       --out my_delegations.json \
       --chain kurtosis \
       local \
       --secret-keys 0xabc123...,0xdef456..
   ```

2. Using an Ethereum keystore file:

   ```text
   bolt-delegations-cli generate \
       --delegatee-pubkey 0x7890ab... \
       --out my_delegations.json \
       --chain kurtosis \
        keystore \
       --path /keys \
       --password myS3cr3tP@ssw0rd
   ```

When using the `keystore` key source, the `--path` flag should point to the directory
containing the encrypted keypair directories.

In case of validator-specific passwords (e.g. Lighthouse format) the `--password-path`
flag must be used instead of `--password`, pointing to the directory containing the password files.

You can find a reference Lighthouse keystore [here](./test_data/lighthouse/).

#### Supported Chains

The tool supports the following chains:

- `mainnet`
- `holesky`
- `helder`
- `kurtosis`

Each chain has its specific fork version used in computing the signing root.
