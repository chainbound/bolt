# Holesky Validator Opt-in Quick Start Guide

> [!IMPORTANT]
> This quick guide skips the details and provides a step-by-step practical guide
> to opt-in to Bolt on the Holesky testnet.
>
> You need to have at least 1 Holesky validator node running to opt-in to Bolt.
> This includes an Execution client, a Beacon client, and a Validator client,
> and at least 1 beacon chain deposit of 32 ETH.

## 0. Pre-requisites

You will need the following dependencies on your machine:

- [Install Docker](https://docs.docker.com/get-docker/)

Additionally, you will need:

- A running Holesky validator node (at least 32 ETH deposited in the beacon chain)
  - Control of your private keys (e.g. a local keystore directory or remote Dirk instance)
- A Holesky wallet funded with a few testnet ETH

## 1. Clone the bolt repository

```bash
git clone https://github.com/chainbound/bolt && cd bolt
```

## 2. Install the bolt CLI

To install the bolt CLI, you can either use our pre-built binaries or build it from source.

### Using pre-built binaries

```bash
# download the bolt-cli installer
curl -L https://raw.githubusercontent.com/chainbound/bolt/unstable/boltup/install.sh | bash

# start a new shell to use the boltup installer
exec $SHELL

# install the bolt-cli binary for holesky
boltup --tag v0.1.0

# check for successful installation
bolt --help
```

### Building from source

You will need the following dependencies to build the bolt CLI yourself:

- [Install Rust](https://www.rust-lang.org/tools/install)
- [Install Protoc](https://grpc.io/docs/protoc-installation/)

```bash
cd bolt-cli
cargo install --force --path .

# check for successful installation
bolt --help
```

## 3. Obtain a list of your validator public keys

This CLI command will list all the public keys of your validator(s) and save them
in a `pubkeys.json` file in the current directory. It works with different key sources
depending on where your keys are stored:

<details>
<summary>If your keys are stored in a local keystore directory</summary>

- NOTE: Right now the `local-keystore` source only supports `lighthouse` style keystores
  (with `validators` and `secrets` subdirectories containing the keystores and passwords respectively).

```bash
bolt pubkeys local-keystore --path <validators_path>
```

Example file structure when using `local-keystore` source:

```bash
- validator_keys
    - validators
        - 0x1234567890...abcde
            - voting-keystore.json
        - 0xabcdef1234...567890
        - validator_definitions.yml
    - secrets
        - 0x1234567890...abcdef
        - 0xabcdef1234...567890
```

In this case you would run the command (called from the `validator_keys` directory):

```bash
bolt pubkeys local-keystore --path validators
```

</details>

<details>
<summary>If your keys are stored on a remote Dirk instance</summary>

- NOTE: You will need to have a running Dirk instance and the necessary TLS certificates to access
  the wallets inside it.

```bash
bolt pubkeys dirk --url <dirk_url> \
  --client-cert-path <client_cert_path> \
  --client-key-path <client_key_path> \
  --ca-cert-path <ca_cert_path> \
  --wallet-path <wallet_path> --passphrases <passphrase>
```

Example Dirk setup might look like this:

```bash
- dirk
    - client_1.crt
    - client_1.key
    - ca.crt
```

</details>

## 4. Register your validators in the `BoltValidators` contract

- NOTE: Before running this command, make sure you have the `pubkeys.json` file generated in the previous step.
- NOTE: You will need a new wallet to use as **operator** for the validators (`--authorized-operator` flag).
  You can generate a new keypair using [`cast wallet new`](https://book.getfoundry.sh/reference/cast/cast-wallet-new) if needed.

```bash
bolt validators register \
    --rpc-url http://localhost:8545 \
    --max-committed-gas-limit 10000000 \
    --authorized-operator <operator_address> \
    --pubkeys-path pubkeys.json \
    --admin-private-key <admin_wallet_private_key>
```

Where:

- `--rpc-url` is the URL of an Ethereum execution node (e.g. Geth) to send transactions to
- `--max-committed-gas-limit` is the maximum gas limit for the committed transactions
- `--authorized-operator` is the **address of the operator that will be authorized to sign commitments**
- `--pubkeys-path` is the path to the `pubkeys.json` file generated in the previous step
- `--admin-private-key` is the private key of the **admin account** that will register the validators
  (as such, it needs to be a wallet with some testnet ETH to pay for gas)

> [!IMPORTANT]
> Pay extra attention to the `--authorized-operator` flag. This is the address that will be authorized to sign
> commitments for your validators and that will have restaked collateral bound to it.
>
> Make sure to have the private key of this address stored securely.
>
> It _does not need_ to be the same as the admin account, but you can use the same address if you want.

## 5. Register your operator in a restaking protocol

We support both `Symbiotic` and `Eigenlayer` as restaking protocols that can be used to provide collateral to
your operator address.

Here we provide a quick guide on how to register with both, but you can choose the one you prefer.

<details>
<summary>Guide to register with Symbiotic</summary>

First, you'll need to install the [Symbiotic CLI](https://docs.symbiotic.fi/guides/cli/).
Then you can follow these steps to register your operator:

1. Register your operator address as a Symbiotic operator with
   [register-operator](https://docs.symbiotic.fi/guides/cli/#register-operator):

   ```bash
   python3 symb.py --chain holesky \
       --provider http://localhost:8545 \
       register-operator \
       --private-key <operator_private_key>
   ```

2. Opt-in to the Bolt network with your operator address with
   [opt-in-network](https://docs.symbiotic.fi/guides/cli/#opt-in-network):

   Note: `0xb017...D2a4` is the Bolt symbiotic network address on Holesky.
   You can find the full list of deployments
   [here](https://github.com/chainbound/bolt/blob/unstable/bolt-contracts/config/holesky/deployments.json).

   ```bash
   python3 symb.py --chain holesky \
       --provider http://localhost:8545 \
       opt-in-network 0xb017002D8024d8c8870A5CECeFCc63887650D2a4 \
       --private-key <operator_private_key>
   ```

3. Opt-in to any vault you want to use with [opt-in-vault](https://docs.symbiotic.fi/guides/cli/#opt-in-vault):

   [Here](https://github.com/chainbound/bolt/tree/unstable/guides/holesky#on-chain-registration)
   is a list of the available vaults. We recommend using the `wETH` vault address for testing
   if you are not familiar with vault policies.

   The wETH vault is deployed at: `0xC56Ba584929c6f381744fA2d7a028fA927817f2b`

   ```bash
   python3 symb.py --chain holesky \
       --provider http://localhost:8545 \
       opt-in-vault <vault_address> \
       --private-key <operator_private_key>
   ```

4. Deposit collateral into the vault you opted-in to with
   [deposit](https://docs.symbiotic.fi/guides/cli/#deposit):

   Here you can re-use the same vault address as above. The amount should be in ETH (e.g. '1' for 1 ETH).
   You MUST set the `on_behalf_of` address (i.e. the third argument in the below command) to your **operator** address.

   - NOTE: You need to hold the respective token that the vault accepts in your operator wallet (wstETH rETH stETH wETH cbETH mETH).
     Otherwise you will receive an error (Failed! Reason: 0x1425ea42).

   ```bash
   python3 symb.py --chain holesky \
       --provider http://localhost:8545 \
       deposit <vault_address> <amount> <operator_address> \
       --private-key <operator_private_key>
   ```

5. Finally register into the BoltManager contract with `bolt` CLI:

   - NOTE: The `--operator-rpc` flag MUST be set to a PUBLICLY ACCESSIBLE URL. This is where your bolt-sidecar will
     receive commitment requests from users and reply with signed commitments. For instance, you can simply use your IP
     address and port (e.g. `--operator-rpc http://<public_ip>:<port`) AND make sure to open the <port> on your firewall.
     The <port> here refers to the port where the bolt-sidecar commitments-api server is running.
     By default it is `8017` and can be changed in the sidecar configuration file.
   - NOTE: If you are using a firewall such as `ufw`, you can open the port with the following command:
     `sudo ufw allow from <your_ip> to any port 8017`.
   - WARNING: Do NOT set the `--operator-rpc` flag to `localhost` or things like `infura.io` as they will not work.

   ```bash
   bolt operators symbiotic register \
       --rpc-url http://localhost:8545 \
       --operator-private-key <operator_private_key> \
       --operator-rpc <operator_rpc_url>
   ```

6. Check your operator status to ensure everything is set up correctly:

   ```bash
   bolt operators symbiotic status \
       --rpc-url http://localhost:8545 \
       --address <operator_address>
   ```

</details>

<details>
<summary>Guide to register with Eigenlayer</summary>

First, you need to install the
[Eigenlayer CLI](https://docs.eigenlayer.xyz/eigenlayer/operator-guides/operator-installation#cli-installation).

1. If you're not registered as an Eigenlayer operator yet, you need to do so by following
   [their official guide](https://docs.eigenlayer.xyz/eigenlayer/operator-guides/operator-installation#operator-configuration-and-registration).

   ```bash
   eigenlayer operator register operator.yaml
   ```

2. Deposit collateral into an Eigenlayer Strategy using the bolt CLI:

   - NOTE: this command will call the [`StrategyManager.depositIntoStrategy`](https://github.com/Layr-Labs/eigenlayer-contracts/blob/testnet-holesky/src/contracts/core/StrategyManager.sol#L303-L322) function in the Eigenlayer contracts.

   ```bash
   bolt operators eigenlayer deposit \
         --rpc-url http://localhost:8545 \
         --operator-private-key <operator_private_key> \
         --strategy <strategy_name> \
         --amount <amount>
   ```

   Where:

   - `--rpc-url` is the URL of the Ethereum node to send transactions to (e.g. Geth)
   - `--operator-private-key` is the private key of your registered operator address
   - `--strategy` is the **NAME** of the strategy to deposit into. [possible values: st-eth, r-eth, w-eth, cb-eth, m-eth].
   - `--amount` is the amount to deposit into the strategy (e.g. '1ether', '0.1ether', '100gwei', etc.)

3. Register into the Bolt AVS:

   - NOTE: The `--operator-rpc` flag MUST be set to a PUBLICLY ACCESSIBLE URL. Since bolt v0.4.0-alpha, the default configuration
     is firewall delegation, which means that your `--operator-rpc` will be set to our Bolt RPC: `https://rpc.holesky.boltprotocol.xyz/rpc`.
     Note that the value above is _exactly_ what you should register on-chain for the Bolt RPC.
   - NOTE: if you do not want to use firewall delegation, you should register a public endpoint (e.g. `--operator-rpc http://<public_ip>:<port`). Make sure to open the `<port>` on your firewall. By default, it is set to `8017`, but it can be changed in the
     sidecar configuration file.
   - NOTE: If you are using a firewall such as `ufw`, you can open the port with the following command:
     `sudo ufw allow from <your_ip> to any port 8017`.
   - WARNING: Do NOT set the `--operator-rpc` flag to `localhost` or things like `infura.io` as they will not work.

   ```bash
    bolt operators eigenlayer register \
        --rpc-url http://localhost:8545 \
        --operator-private-key <operator_private_key> \
        --operator-rpc <operator_rpc> \
        --salt <SALT>
   ```

   Where:

   - `--rpc-url` is the URL of the Ethereum node to send transactions to (e.g. Geth)
   - `--operator-private-key` is the private key of your registered operator address
   - `--operator-rpc` is the URL of the operator's RPC server (e.g. `http://<ip>:<port>`)
   - `--salt` is a unique 32 bytes value to add replay attacks. To generate one (on MacOS or linux)
     you can run:

     ```bash
     echo -n "0x"; head -c 32 /dev/urandom | hexdump -e '32/1 "%02x" "\n"'
     ```

4. Check your operator status to ensure everything is set up correctly:

   ```bash
   bolt operators eigenlayer status \
       --rpc-url http://localhost:8545 \
       --address <operator_address>
   ```

</details>

## 6. Start the Bolt Sidecar + Mev-Boost setup

There are two modes in which the Bolt-sidecar can be run:

1. Docker mode (recommended)
2. Commit-boost mode

In this section we're going to cover the Docker mode, while the Commit-boost mode is covered in a
separate guide [here](./commit-boost/README.md) in detail.

### Docker mode

First, change directory to the `guides/holesky` folder in the bolt repository
you cloned in step 1:

```bash
cd guides/holesky
```

In this directory you will find a `docker-compose.yml` file that you can use to
start the bolt sidecar. But before doing that, you will need to change the
configuration file to match your setup.

To get started with the configuration, copy the following preset file:

```bash
cp ./presets/sidecar-delegations-preset.env.example bolt-sidecar.env
```

This preset file will run the bolt-sidecar with a pre-authorized signer specified in the delegations file, as well
as enable firewall delegation. This is the recommended way to run the sidecar.

Fill the configuration excluding the "Signing options"
section, which will be covered below. Remember to set the
`BOLT_SIDECAR_OPERATOR_PRIVATE_KEY` to the operator private key registered in
the previous step.

**Why firewall delegation?**
Firewall delegation allows proposers to set an external third party as their network entrypoint or _firewall_. It gets rid of the
requirement to expose an HTTP RPC endpoint for accepting inclusion requests (inbound), and instead subscribes to the configured firewall over a
websocket connection (outbound). The firewall will then stream valid, filtered inclusion requests over the websocket connection.

Some of the other duties of the firewall include:

- Spam and DoS prevention
- Pricing inclusion requests correctly (see more below)
- Communicating prices with consumers (wallets, users)

Currently, we operate a firewall RPC on Holesky at `wss://rpc.holesky.boltprotocol.xyz/api/v1/firewall_stream`.

Read more about firewall delegation [here](https://x.com/boltprotocol_/status/1879571451621077413).

**Why authorizations?**

The bolt-sidecar needs to know which validators it is controlling (aka, which validators it can sign commitments
on behalf of). Otherwise it may sign commitments for random validators which would get you slashed.

We could use the validator keys directly to do this, but that would entail loading them into the bolt-sidecar,
which is not the best in terms of security and operational practices.

For this reason, the bolt-sidecar uses an authorization mechanism that allows it to authenticate a different key
(the "delegatee") as a valid signer for a given validator. All we need to do is use the validator key once
to sign a message that essentially says "I authorize this other key to sign commitments on my behalf".

This way, operators don't need to use their validator secret keys in their online sidecar setup anymore.

**Creating authorizations**

In order to create and use these delegations, you can follow these steps:

1. Use the `bolt` CLI to generate signed delegation message for your validators:

   - Note: this step is similar to the `bolt pubkeys` command used in step 3 of this quick guide.
   - Note: this command can be run _offline_.
   - Note: you can generate a fresh BLS keypair using `bolt generate bls` if you don't have one.

   ```bash
    bolt delegate --delegatee-pubkey <delegatee_pubkey> local-keystore --path <validators_path> --password-path <secrets_path>
   ```

   Similarly, you can use `dirk` as the source if you are using a remote Dirk instance as opposed to a local keystore.

   This command will output a "delegations.json" file in the current directory.

2. Open the `bolt-sidecar.env` file and set:

   - `BOLT_SIDECAR_CONSTRAINT_PRIVATE_KEY`: the private key of which the public key was used to generate the delegation message
     (as `--delegatee-pubkey` in the previous step).
   - `BOLT_SIDECAR_DELEGATIONS_PATH`: `delegations.json` (name of the file generated in the previous step).

That's it! You can proceed to the next step.

**Configuring MEV-Boost**

After you've filled out the sidecar configuration, you can do the same with the `mev-boost` configuration:

```bash
cp mev-boost.env.example mev-boost.env
```

And fill out the values in the `mev-boost.env` file as well.

- NOTE: the config file comes with relay URLs already set up for you. Feel free to change them if
  you only want to use some specific relays.

**Start the docker compose**

Once the config files are in place, make sure you have Docker running and then start the docker compose:

```bash
docker compose --env-file bolt-sidecar.env up -d
```

The docker compose setup comes with various observability tools, such as Prometheus and Grafana.
It also comes with some pre-built dashboards which you can find at `http://localhost:28017`.
