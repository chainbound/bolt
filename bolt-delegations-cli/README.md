# Bolt Delegations CLI

`bolt-delegations-cli` is a command-line tool for generating delegation messages signed with a BLS (Boneh–Lynn–Shacham) key. This tool allows node operators to safely generate delegations offline, enabling an air-gapped workflow to secure sensitive information like validator keys.

The tool supports two key sources:

-   Local: A BLS private key provided directly from a file.
-   Keystore: A keystore file that contains an encrypted BLS private key, with the set [default password](https://github.com/chainbound/bolt/blob/a935fb36d75c997a4edb834f27a56bc62eb3570c/bolt-delegations-cli/src/utils.rs#L11).

Features:

-   Offline usage: Safely generate delegation messages in an offline environment.
-   Flexible key source: Support for both direct local BLS private keys and Ethereum keystore files (ERC-2335 format).
-   BLS delegation signing: Sign delegation messages using a BLS secret key and output the signed delegation in JSON format.

## Usage

```bash
A CLI tool to generate signed delegation messages for BLS keys

Usage: bolt-delegations-cli <COMMAND>

Commands:
  generate  Generate delegation messages
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

### Example

1. Using a local BLS private key:

    ```bash
    bolt-delegations-cli generate \
        --source local \
        --key-path ./private_key.txt \
        --delegatee-pubkey 0x83eeddfac5e60f8fe607ee8713efb8877c295ad9f8ca075f4d8f6f2ae241a30dd57f78f6f3863a9fe0d5b5db9d550b93 \
        --out ./delegations.json \
        --chain kurtosis
    ```

2. Using an Ethereum keystore file:

    ```bash
    bolt-delegations-cli generate \
        --source keystore \
        --key-path ./keystore.json \
        --delegatee-pubkey 0x83eeddfac5e60f8fe607ee8713efb8877c295ad9f8ca075f4d8f6f2ae241a30dd57f78f6f3863a9fe0d5b5db9d550b93 \
        --out ./delegations.json \
        --chain kurtosis
    ```

3. Using `.env` file:

    Refer `.env.example` for the required environment variables.

    ```env
    SOURCE=local
    KEY_PATH=private_key.txt
    DELEGATEE_PUBKEY=0x95b4b2371fd882d98dc14e900578f927428d1cb6486f0b1483c9a8f659e90f19504f607b2d7a7a8046c637e40ca81e26
    OUTPUT_FILE_PATH=delegations.json
    CHAIN=kurtosis
    ```
