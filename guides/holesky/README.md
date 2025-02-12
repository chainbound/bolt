# Holesky Launch Instructions

This document provides instructions for running Bolt on the Holesky testnet.

> [!IMPORTANT]
> Other than this guide, we also have a [Quick Start Guide](./QUICK_START.md) that provides
> a more concise and straightforward practical guide to running Bolt on Holesky.
>
> This page contains more detailed information and architecture explanations.

# Table of Contents

<!-- vim-markdown-toc GFM -->

* [Prerequisites](#prerequisites)
* [On-Chain Registration](#on-chain-registration)
  * [Validator Registration](#validator-registration)
    * [Registration Steps](#registration-steps)
  * [Bolt Network Entrypoint](#bolt-network-entrypoint)
  * [Operator Registration](#operator-registration)
    * [Symbiotic Registration Steps](#symbiotic-registration-steps)
    * [EigenLayer Registration Steps](#eigenlayer-registration-steps)
* [Off-Chain Setup](#off-chain-setup)
  * [Docker Mode (recommended)](#docker-mode-recommended)
  * [Commit-Boost Mode](#commit-boost-mode)
  * [Native Mode (advanced)](#native-mode-advanced)
    * [Building and running the MEV-Boost fork binary](#building-and-running-the-mev-boost-fork-binary)
    * [Building and running the Bolt sidecar binary](#building-and-running-the-bolt-sidecar-binary)
      * [Configuration file](#configuration-file)
  * [Observability](#observability)
  * [Firewall Delegation](#firewall-delegation)
* [Reference](#reference)
  * [Supported RPC nodes](#supported-rpc-nodes)
  * [Supported Relays](#supported-relays)
  * [Command-line options](#command-line-options)
  * [Delegations and signing options for Native and Docker Compose Mode](#delegations-and-signing-options-for-native-and-docker-compose-mode)
    * [`bolt` CLI](#bolt-cli)
      * [Installation and usage](#installation-and-usage)
    * [Using a private key directly](#using-a-private-key-directly)
    * [Using a ERC-2335 Keystore](#using-a-erc-2335-keystore)
  * [Avoid restarting the beacon node](#avoid-restarting-the-beacon-node)
  * [Vouch configuration](#vouch-configuration)
    * [`execution_config.json`](#execution_configjson)

<!-- vim-markdown-toc -->

<!-- Links -->

[bolt]: https://docs.boltprotocol.xyz
[constraints-api]: https://docs.boltprotocol.xyz/technical-docs/api/builder

# Prerequisites

In order to run Bolt you need some components already installed and running on
your system.

**A synced Geth client:**

Bolt is fully trustless since it is able to produce a fallback block with the
commitments issued in case builders do not return a valid bid. In order to do so
it relies on a synced execution client, configured via the `--execution-api-url`
flag. **At the moment only Geth is supported; with more
clients to be supported in the future.**

Using the sidecar with a different execution client could lead to commitment
faults because fallback block building is not supported yet. You can download
Geth from [the official website](https://geth.ethereum.org/downloads).

**A synced beacon node:**

Bolt is compatible with every beacon client. Please refer to the various beacon
client implementations to download and run them.

> [!IMPORTANT]
> In order to correctly run the Bolt sidecar and avoid commitment faults the
> beacon node and the validator client must be configured so that:
>
> 1. the node's `builder-api` (or equivalent flag) must point to the Bolt
>    Sidecar API.
> 2. the node and the validator client will always prefer the builder payload,
>    and try to use the builder API. For instance, in Lighthouse this can be
>    done by setting the `builder-fallback-disable-checks` flag and the
>    `builder-boost-factor` to a large value like `18446744073709551615`
>    (`2**64 - 1`).
>
> It might be necessary to restart your beacon node depending on your existing
> setup. See the [Avoid Restarting the Beacon
> Node](#avoid-restarting-the-beacon-node) section for more details.

**Active validators:**

The Bolt sidecar requires access to BLS signing keys from active Ethereum validators,
or **authorized delegates** acting on their behalf, to issue and sign preconfirmations.

To learn more about delegation, check out the [Delegations and Signing](#delegations-and-signing-options-for-native-and-docker-compose-mode)
section.

> [!NOTE]
> Before moving on to the actual instructions, please note that the on-chain steps must be completed before running the off-chain
> infrastructure. The sidecar will verify that all of the associated validators and operator have been registered in the Bolt contracts,
> else it will fail (for safety reasons).

# On-Chain Registration

The first step for integrating Bolt is registering into the Bolt smart contracts. This is required for signalling
participation, depositing collateral, and specifying endpoints and other metadata to start receiving preconfirmation
requests. What follows is a quick overview of the required steps.

First you'll need to deposit some collateral in the form of whitelisted ETH derivative tokens that need to
be restaked in either the Symbiotic or EigenLayer restaking protocols. Bolt is compatible with the following ETH derivative tokens on Holesky:

- [Symbiotic Vaults](https://docs.symbiotic.fi/deployments/current#vaults)
  - [`wstETH`](https://holesky.etherscan.io/address/0xc79c533a77691641d52ebD5e87E51dCbCaeb0D78)
  - [`rETH`](https://holesky.etherscan.io/address/0xe5708788c90e971f73D928b7c5A8FD09137010e0)
  - [`stETH`](https://holesky.etherscan.io/address/0x11c5b9A9cd8269580aDDbeE38857eE451c1CFacd)
  - [`wETH`](https://holesky.etherscan.io/address/0xC56Ba584929c6f381744fA2d7a028fA927817f2b)
  - [`cbETH`](https://holesky.etherscan.io/address/0xcDdeFfcD2bA579B8801af1d603812fF64c301462)
  - [`mETH`](https://holesky.etherscan.io/address/0x91e84e12Bb65576C0a6614c5E6EbbB2eA595E10f)
- [EigenLayer Strategies](https://github.com/Layr-Labs/eigenlayer-contracts#current-testnet-deployment)
  - [`stETH`](https://holesky.etherscan.io/address/0x3F1c547b21f65e10480dE3ad8E19fAAC46C95034)
  - [`rETH`](https://holesky.etherscan.io/address/0x7322c24752f79c05FFD1E2a6FCB97020C1C264F1)
  - [`wETH`](https://holesky.etherscan.io/address/0x94373a4919B3240D86eA41593D5eBa789FEF3848)
  - [`cbETH`](https://holesky.etherscan.io/address/0x8720095Fa5739Ab051799211B146a2EEE4Dd8B37)
  - [`mETH`](https://holesky.etherscan.io/address/0xe3C063B1BEe9de02eb28352b55D49D85514C67FF)

> [!NOTE]
> These Vaults and Strategies have been deployed on Holesky by us, and are permissionless to opt in to.
> For now, these are the only vaults & strategies that have been whitelisted by the Bolt protocol.

After that, you need to interact with two contracts on Holesky:

- `BoltValidators`, used to register your active validators into bolt
- `BoltManager`, used to register as an **operator** into the system and integrate with restaking protocols.

> [!IMPORTANT]
> When registering your **operator** in the `BoltManager` contract you MUST use the
> Ethereum address for which you specify the private key as the `--commitment-private-key`
> flag in the Bolt Sidecar configuration.
>
> In other words, the `commitment-private-key` flag MUST be set to the private key of the Ethereum
> address that is registered as operator in the `BoltManager` contract for your validators to be
> able to sign valid commitments.

**Prerequisites**

- Make sure you have Rust installed on your machine. Follow the instructions
  reported in the [official website](https://www.rust-lang.org/tools/install).

- Clone the Bolt repo and install the `bolt` CLI

  ```bash
  git clone https://github.com/chainbound/bolt
  cd bolt-cli
  cargo install --force --path .
  ```

The command above will install the `bolt` CLI in your system, which is a useful tool to
manage your validators and operators in the bolt Protocol. You can check if
it's installed by running `bolt --help`.

```text
`bolt` is a CLI tool to interact with bolt Protocol ✨

Usage: bolt <COMMAND>

Commands:
  delegate    Generate BLS delegation or revocation messages
  pubkeys     Output a list of pubkeys in JSON format
  send        Send a preconfirmation request to a bolt proposer
  validators  Handle validators in the bolt network
  operators   Handle operators in the bolt network
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

> [!NOTE]
> All the `bolt` commands can be simulated on a Holesky fork using Anvil with
> the following command:
>
> `anvil --fork-url https://holesky.drpc.org --port 8545`
>
> In order to use this local fork, replace the `--rpc-url` flag (`$RPC_URL` env)
> with `http://localhost:8545` in all `bolt` commands below.

## Validator Registration

The [`BoltValidators`](../../bolt-contracts/src/contracts/BoltValidatorsV1.sol) contract is the only
point of entry for validators to signal their intent to participate in Bolt
Protocol and authenticate with their BLS private key (unsupported until Pectra).

The registration process includes the following steps:

1. Validator signs a message with their BLS private key. This is required to
   prove that the validator private key is under their control and that they are
   indeed its owner.
2. Validator calls the `registerValidator` function providing:
   1. Their BLS public key
   2. The BLS signature of the registration message
   3. The address of the authorized collateral provider & operator (commitment signer)

Until the Pectra hard-fork will be activated, the contract will also expose a
`registerValidatorUnsafe` function that will not check the BLS signature. This
is gated by a feature flag that will be turned off post-Pectra and will allow us
to test the registration flow in a controlled environment.

Note that the account initiating the registration will be the `controller`
account for those validators. Only the `controller` can then deregister
validator or change any preferences.

### Registration Steps

To register your validators, you can use the `bolt` CLI. First, look at the
options available for the `validators register` command:

```text
Usage: bolt validators register [OPTIONS] --rpc-url <RPC_URL> --max-committed-gas-limit <MAX_COMMITTED_GAS_LIMIT> --authorized-operator <AUTHORIZED_OPERATOR> --admin-private-key <ADMIN_PRIVATE_KEY>

Options:
      --rpc-url <RPC_URL>
          The URL of the RPC to broadcast the transaction [env: RPC_URL=]
      --max-committed-gas-limit <MAX_COMMITTED_GAS_LIMIT>
          The max gas limit the validator is willing to reserve to commitments [env: MAX_COMMITTED_GAS_LIMIT=]
      --authorized-operator <AUTHORIZED_OPERATOR>
          The authorized operator for the validator [env: AUTHORIZED_OPERATOR=]
      --pubkeys-path <PUBKEYS_PATH>
          The path to the JSON pubkeys file, containing an array of BLS public keys [env: PUBKEYS_PATH=] [default: pubkeys.json]
      --admin-private-key <ADMIN_PRIVATE_KEY>
          The private key to sign the transactions with [env: ADMIN_PRIVATE_KEY=]
  -h, --help
          Print help
```

To generate the JSON file containing the pubkeys, you can use the `bolt pubkeys`
command. See `bolt pubkeys --help` for more info.

Fill the required options and run the script. If the script executed
succesfully, your validators were registered.

## Bolt Network Entrypoint

The [`BoltManager`](../../bolt-contracts/src/contracts/BoltManagerV1.sol)
contract is a crucial component of Bolt that integrates with restaking
ecosystems Symbiotic and Eigenlayer. It manages the registration and
coordination of validators, operators, and vaults within the Bolt network.

Key features include:

1. Retrieval of operator stake and proposer status from their pubkey
2. Integration with Symbiotic
3. Integration with Eigenlayer

Specific functionalities about the restaking protocols are handled inside the
`IBoltMiddleware` contracts, such as [`BoltSymbioticMiddleware`](../../bolt-contracts/src/contracts/BoltSymbioticMiddlewareV2.sol) and
[`BoltEigenlayerMiddleware`](../../bolt-contracts/src/contracts/BoltEigenLayerMiddlewareV2.sol).

## Operator Registration

In this section we outline how to register as an operator, i.e. an entity
uniquely identified by an Ethereum address and responsible for duties like
signing commitments. Note that in Bolt, there is no real separation between
validators and an operator. An operator is only real in the sense that its
private key will be used to sign commitments on the corresponding validators'
sidecars. However, we need a way to logically connect validators to an on-chain
address associated with some stake, which is what the operator abstraction takes care of.

### Symbiotic Registration Steps

As an operator, you will need to opt-in to the Bolt Network and any Vault that
trusts you to provide commitments on their behalf.

**External Steps**

> [!NOTE]
> The network and supported vault addresses can be found in
> [`deployments.json`](../../bolt-contracts/config/holesky/deployments.json).

Make sure you have installed the [Symbiotic
CLI](https://docs.symbiotic.fi/guides/cli/).

The opt-in process requires the following steps:

1. if you haven't done it already, register as a Symbiotic Operator with the
   [`register-operator`](https://docs.symbiotic.fi/guides/cli/#register-operator)
   command;
2. opt-in to the Bolt network with the
   [`opt-in-network`](https://docs.symbiotic.fi/guides/cli/#opt-in-network)
   command;
3. opt-in to any vault using the
   [`opt-in-vault`](https://docs.symbiotic.fi/guides/cli/#opt-in-vault) command;
4. deposit collateral into the vault using the
   [`deposit`](https://docs.symbiotic.fi/guides/cli/#deposit) command. For this deployment,
   you have to deposit `1 ether` of the collateral token.

**Internal Steps**

After having deposited collateral into a vault you need to register into
Bolt as a Symbiotic operator. You can do that using the `bolt` CLI.

First, read the requirements for the `bolt operator symbiotic register` command:

```text
Register into the bolt manager contract as a Symbiotic operator

Usage: bolt operators symbiotic register --rpc-url <RPC_URL> --operator-private-key <OPERATOR_PRIVATE_KEY> --operator-rpc <OPERATOR_RPC>

Options:
      --rpc-url <RPC_URL>
          The URL of the RPC to broadcast the transaction [env: RPC_URL=]
      --operator-private-key <OPERATOR_PRIVATE_KEY>
          The private key of the operator [env: OPERATOR_PRIVATE_KEY=]
      --operator-rpc <OPERATOR_RPC>
          The URL of the operator RPC [env: OPERATOR_RPC=]
  -h, --help
          Print help
```

Fill the required options and run the script. If the script executed
successfully, your validators were registered.

> [!IMPORTANT]
> If you want to run in firewall delegation mode, set the `--operator-rpc` to `https://rpc.holesky.boltprotocol.xyz/rpc`.
> Firewall delegation is covered [here](#firewall-delegation).

To check your operator status, you can use the `bolt operator
symbiotic status` command:

```text
Check the status of a Symbiotic operator

Usage: bolt operators symbiotic status --rpc-url <RPC_URL> --address <ADDRESS>

Options:
      --rpc-url <RPC_URL>  The URL of the RPC to broadcast the transaction [env: RPC_URL=]
      --address <ADDRESS>  The address of the operator to check [env: OPERATOR_ADDRESS=]
  -h, --help               Print help
```

### EigenLayer Registration Steps

**External Steps**

> [!NOTE]
> The supported strategies can be found in
> [`deployments.json`](../../bolt-contracts/config/holesky/deployments.json).

If you're not registered as an operator in EigenLayer yet, you need to do so by
following [the official
guide](https://docs.eigenlayer.xyz/eigenlayer/operator-guides/operator-introduction).
This requires installing the EigenLayer CLI and opt into the protocol by
registering via the
[`DelegationManager.registerAsOperator`](https://docs.eigenlayer.xyz/eigenlayer/operator-guides/operator-installation)
function.

After that you need to deposit into a supported EigenLayer
strategy using
[`StrategyManager.depositIntoStrategy`](https://github.com/Layr-Labs/eigenlayer-contracts/blob/testnet-holesky/src/contracts/core/StrategyManager.sol#L303-L322).
This will add the deposit into the collateral of the operator so that Bolt can
read it. Note that you need to deposit a minimum of `1 ether` of the strategies
underlying token in order to opt in.

You can deposit into a strategy by using the following `bolt operators
eigenlayer deposit` command:

```text
Step 1: Deposit into a strategy

Usage: bolt operators eigenlayer deposit --rpc-url <RPC_URL> --operator-private-key <OPERATOR_PRIVATE_KEY> --strategy <STRATEGY> --amount <AMOUNT>

Options:
      --rpc-url <RPC_URL>
          The URL of the RPC to broadcast the transaction [env: RPC_URL=]
      --operator-private-key <OPERATOR_PRIVATE_KEY>
          The private key of the operator [env: OPERATOR_PRIVATE_KEY=]
      --strategy <STRATEGY>
          The name of the strategy to deposit into [env: EIGENLAYER_STRATEGY=] [possible values: st-eth, r-eth, w-eth, cb-eth, m-eth]
      --amount <AMOUNT>
          The amount to deposit into the strategy. (examples: "1ether", "0.2ether", "100gwei") [env: EIGENLAYER_STRATEGY_DEPOSIT_AMOUNT=]
  -h, --help
          Print help
```

Note that the amount is in ETH, so if you want to deposit `1 ether` you need to
provide `--amount 1`.

Fill the required options and run the script. If the script executed
successfully, you have deposited into the strategy.

**Internal Steps**

After having deposited collateral into a strategy you need to register into the
Bolt AVS. You can use the `bolt operators eigenlayer register` command for it:

```text
Step 2: Register into the bolt AVS

Usage: bolt operators eigenlayer register --rpc-url <RPC_URL> --operator-private-key <OPERATOR_PRIVATE_KEY> --operator-rpc <OPERATOR_RPC> --salt <SALT>

Options:
      --rpc-url <RPC_URL>
          The URL of the RPC to broadcast the transaction [env: RPC_URL=]
      --operator-private-key <OPERATOR_PRIVATE_KEY>
          The private key of the operator [env: OPERATOR_PRIVATE_KEY=]
      --operator-rpc <OPERATOR_RPC>
          The URL of the operator RPC [env: OPERATOR_RPC=]
      --salt <SALT>
          The salt for the operator signature [env: OPERATOR_SIGNATURE_SALT=]
  -h, --help
          Print help
```

> [!IMPORTANT]
> If you want to run in firewall delegation mode, set the `--operator-rpc` to `https://rpc.holesky.boltprotocol.xyz/rpc`.
> Firewall delegation is covered [here](#firewall-delegation).

A note on the `--salt` parameter:

- `salt` -- an unique 32 bytes value to avoid replay attacks. To generate it on
  both Linux and MacOS you can run:

  ```bash
  echo -n "0x"; head -c 32 /dev/urandom | hexdump -e '32/1 "%02x" "\n"'
  ```

Once you have the required values, fill the options and run the script. If the
command executed successfully, your operator were registered into bolt.

To check if the status of your operator, you can use the `bolt operators
eigenlayer status` command:

```bash
Step 3: Check your operation registration in bolt

Usage: bolt operators eigenlayer status --rpc-url <RPC_URL> --address <ADDRESS>

Options:
      --rpc-url <RPC_URL>  The URL of the RPC to broadcast the transaction [env: RPC_URL=]
      --address <ADDRESS>  The address of the operator to check [env: OPERATOR_ADDRESS=]
  -h, --help               Print help
```

# Off-Chain Setup

After all of the steps above have been completed, we can proceed with running the off-chain infrastructure.

## Beacon Node

Bolt only uses standardized APIs to interact with the beacon node, so any beacon node implementation should work. However, you will need to configure the beacon node
with some flags to make sure it doesn't fall back to execution client blocks and ignores blocks from the Bolt sidecar (using Lighthouse flags as examples):

- `--builder-boost-factor` or equivalent flag should be set to a large value like `18446744073709551615` (`2**64 - 1`). This will ensure that payloads from Bolt always
  have priority over EL payloads.
  - In [Prysm](https://docs.prylabs.network/docs/advanced/builder#prioritizing-local-blocks), set `--local-block-value-boost` to 0.
- `--builder-fallback-disable-checks` or equivalent flag should be set to true. This will ensure that the beacon node doesn't fall back to execution client blocks when
  [circuit breaker conditions](https://lighthouse-book.sigmaprime.io/builders.html#circuit-breaker-conditions) are met.
  - In [Prysm](https://docs.prylabs.network/docs/advanced/builder#circuit-breaker), set `--max-builder-consecutive-missed-slots` and `--max-builder-epoch-missed-slots` to 32.

There are various way to run the Bolt Sidecar depending on your preferences and your preferred signing methods:

1. Docker mode (recommended)
2. [Commit-Boost](https://commit-boost.github.io/commit-boost-client) mode (requires Docker)
3. Native mode (advanced, requires building everything from source)

In this section we're going to explore each of these options and its
requirements.

## Docker Mode (recommended)

First, make sure to have [Docker](https://docs.docker.com/engine/install/),
[Docker Compose](https://docs.docker.com/compose/install/) and
[git](https://git-scm.com/downloads) installed in your machine.

Then clone the Bolt repository by running:

```bash
git clone htts://github.com/chainbound/bolt.git
cd bolt/guides/holesky
```

The Docker Compose setup will spin up the Bolt sidecar along with the Bolt
MEV-Boost fork which includes supports the [Constraints API][constraints-api].

Before starting the services, you'll need to provide configuration files
containing the necessary environment variables:

1. **Bolt Sidecar Configuration:**

   Change directory to `guides/holesky` if you haven't already, and create a
   `bolt-sidecar.env` file starting from the reference template:

   ```bash
   cp bolt-sidecar.env.example bolt-sidecar.env
   ```

   Next up, fill out the values that are left blank. Please also review the
   default values and see that they work for your setup. For proper
   configuration of the signing options, please refer to the [Delegations and
   Signing](#delegations-and-signing-options-for-native-and-docker-compose-mode)
   section of this guide.

1. **MEV-Boost Configuration:**

   Change directory to the `guides/holesky` folder if you haven't already and
   copy over the example configuration file:

   ```bash
   cp ./mev-boost.env.example ./mev-boost.env
   ```

Then configure it accordingly and review the default values chosen.

If you prefer not to restart your beacon node, follow the instructions in the
[Avoid Restarting the Beacon Node](#avoid-restarting-the-beacon-node) section.

Once the configuration files are in place, make sure you are in the
`guides/holesky` directory and then run:

```bash
docker compose --env-file bolt-sidecar.env up -d
```

The docker compose setup comes with various observability tools, such as
Prometheus and Grafana. It also comes with some pre-built dashboards which you
can find at `http://localhost:28017`.

## Commit-Boost Mode

Please refer to the [Commit-Boost guide](./commit-boost/README.md) for more
information on how to run the Bolt setup with Commit-Boost.

## Native Mode (advanced)

For running the Bolt Sidecar as a standalone binary you need to have the
following dependencies installed:

- [git](https://git-scm.com/downloads);
- [Rust](https://www.rust-lang.org/tools/install).
- [Golang](https://golang.org/doc/install).

Depending on your platform you may need to install additional dependencies.

<details>
<summary><b>Linux</b></summary>

Debian-based distributions:

```bash
sudo apt update && sudo apt install -y git build-essential libssl-dev build-essential ca-certificates
```

Fedora/Red Hat/CentOS distributions:

```bash
sudo dnf groupinstall "Development Tools" && sudo dnf install -y git openssl-devel ca-certificates pkgconfig
```

Arch/Manjaro-based distributions:

```bash
sudo pacman -Syu --needed base-devel git openssl ca-certificates pkgconf
```

Alpine Linux

```bash
sudo apk add git build-base openssl-dev ca-certificates pkgconf
```

</details>

<br>

<details>
  <summary><b>MacOS</b></summary>

On MacOS after installing XCode Command Line tools (equivalent to `build-essential` on Linux) you can install the other dependencies with [Homebew](https://brew.sh/):

```zsh
xcode-select --install
brew install pkg-config openssl
```

</details>

---

After having installed the dependencies you can clone the Bolt repository by
running:

```bash
git clone --branch v0.3.0 https://github.com/chainbound/bolt.git && cd bolt
```

### Building and running the MEV-Boost fork binary

The Bolt protocol relies on a modified version of
[MEV-Boost](https://boost.flashbots.net/) that supports the [Constraints
API][constraints-api]. This modified version is
available in the `mev-boost` directory of the project and can be built by
running

```bash
make build
```

in the `mev-boost` directory. The output of the command is a `mev-boost` binary.
To run the `mev-boost` binary please read the official [documentation](https://boost.flashbots.net/).

If you're already running MEV-Boost along with your beacon client it is
recommended to choose another port this service in order to [avoid restarting
your beacon client](#avoid-restarting-the-beacon-node). Check out the linked
section for more details.

### Building and running the Bolt sidecar binary

Then you can build the Bolt sidecar by running:

```bash
cargo build --release
```

In order to run correctly the sidecar you need to provide either a list command
line options or a configuration file (recommended). All the options available
can be found by running `./bolt-sidecar --help`, or you can find them in the
[reference](#command-line-options) section of this guide.

### Configuration file

You can use a `.env` file to configure the sidecar, for which you can
find a template in the `.env.example` file.

Please read the section on [Delegations and Signing](#delegations-and-signing-options-for-native-and-docker-compose-mode)
to configure such sidecar options properly.

After you've set up the configuration file you can run the Bolt sidecar with

```bash
./target/release/bolt-sidecar
```

## Observability

The bolt sidecar comes with various observability tools, such as Prometheus
and Grafana. It also comes with some pre-built dashboards, which can
be found in the `grafana` directory. If you're running in Docker mode, these are started by default, and you can skip
this section.

To run these dashboards change directory to the `bolt-sidecar/infra` folder, configure `prometheus.yml`, and
run:

```bash
docker compose -f telemetry.compose.yml up -d
```

To stop the services run:

```bash
docker compose -f telemetry.compose.yml down
```

## Firewall Delegation

The Bolt sidecar will run in firewall delegation mode by default (specified in `BOLT_SIDECAR_FIREWALL_RPCS=“wss://rpc.holesky.boltprotocol.xyz/api/v1/firewall_stream”`). This means that it will initiate an outbound connection to the WebSocket endpoint
defined above. It is recommended to run this mode because it will protect you from spam and DoS.

If you wish to disable this, you'll have to expose an endpoint yourself on which to receive inclusion requests.
You can activate this by setting `BOLT_SIDECAR_PORT` to some value, and commenting `BOLT_SIDECAR_FIREWALL_RPCS`, as these are
mutually exclusive. This port should be open on your firewall in order to receive external requests.

For example, on Linux you can use `ufw` rules:

```bash
sudo ufw allow from any to any port $BOLT_SIDECAR_PORT
```

# Reference

## Supported RPC nodes

Currently the only deployed [Bolt RPC](https://docs.boltprotocol.xyz/technical-docs/api/rpc)
API is the one provided by Chainbound:

- [`https://rpc.holesky.boltprotocol.xyz`](https://rpc.holesky.boltprotocol.xyz)
  - RPC entrypoint: [/rpc](https://rpc.holesky.boltprotocol.xyz/rpc)
  - OpenAPI documentation: [/docs](https://rpc.holesky.boltprotocol.xyz/docs)

## Supported Relays

Here is a list of Relays that support the Bolt constraints API and can be used
as PBS relays when running Bolt:

| Relay Name | Chain   | URL                                                                                                                                         |
| ---------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Chainbound | Holesky | https://0xa55c1285d84ba83a5ad26420cd5ad3091e49c55a813eee651cd467db38a8c8e63192f47955e9376f6b42f6d190571cb5@relay-holesky.bolt.chainbound.io |
| Titan      | Holesky | https://0xaa58208899c6105603b74396734a6263cc7d947f444f396a90f7b7d3e65d102aec7e5e5291b27e08d02c50a050825c2f@holesky-preconf.titanrelay.xyz   |
| Aestus     | Holesky | https://0x8d6ff9fdf3b8c05293f6c240f57034c6c5244d7ecb2b9a6e597de575b373610d6345f5060c150012d1cc42d38b8383ac@preconfs-holesky.aestus.live     |
| Bloxroute  | Holesky | https://0x821f2a65afb70e7f2e820a925a9b4c80a159620582c1766b1b09729fec178b11ea22abb3a51f07b288be815a1a2ff516@bloxroute.holesky.blxrbdn.com    |

**Note for Lido CSM validators**

If you are part of the Lido CSM program, you can use the following relays: `Chainbound`, `Titan` and `Aestus`.
See the [related Lido forum discussion](https://research.lido.fi/t/rmc-proposal-add-relays-supporting-proposer-commitments-to-the-holesky-allow-list/8992/4) for more information.

## Command-line options

For completeness, here are all the command-line options available for the Bolt
sidecar. You can see them in your terminal by running the Bolt sidecar binary
with the `--help` flag:

<details>
<summary>CLI help Reference</summary>

```text

Command-line options for the Bolt sidecar

Usage: bolt-sidecar [OPTIONS] --engine-jwt-hex <ENGINE_JWT_HEX> --fee-recipient <FEE_RECIPIENT> --builder-private-key <BUILDER_PRIVATE_KEY> --commitment-private-key <COMMITMENT_PRIVATE_KEY> <--constraint-private-key <CONSTRAINT_PRIVATE_KEY>|--commit-boost-signer-url <COMMIT_BOOST_SIGNER_URL>|--keystore-password <KEYSTORE_PASSWORD>|--keystore-secrets-path <KEYSTORE_SECRETS_PATH>>

Options:
      --port <PORT>
      Port to listen on for incoming JSON-RPC requests of the Commitments API. This port should be open on your firewall in order to receive external requests!

          [env: BOLT_SIDECAR_PORT=]
          [default: 8017]

      --execution-api-url <EXECUTION_API_URL>
          Execution client API URL

          [env: BOLT_SIDECAR_EXECUTION_API_URL=]
          [default: http://localhost:8545]

      --beacon-api-url <BEACON_API_URL>
          URL for the beacon client

          [env: BOLT_SIDECAR_BEACON_API_URL=]
          [default: http://localhost:5052]

      --engine-api-url <ENGINE_API_URL>
          Execution client Engine API URL. This is needed for fallback block building and must be a synced Geth node

          [env: BOLT_SIDECAR_ENGINE_API_URL=]
          [default: http://localhost:8551]

      --constraints-api-url <CONSTRAINTS_API_URL>
          URL to forward the constraints produced by the Bolt sidecar to a server supporting the Constraints API, such as an MEV-Boost fork

          [env: BOLT_SIDECAR_CONSTRAINTS_API_URL=]
          [default: http://localhost:18551]

      --constraints-proxy-port <CONSTRAINTS_PROXY_PORT>
          The port from which the Bolt sidecar will receive Builder-API requests from the Beacon client

          [env: BOLT_SIDECAR_CONSTRAINTS_PROXY_PORT=]
          [default: 18550]

      --engine-jwt-hex <ENGINE_JWT_HEX>
          The JWT secret token to authenticate calls to the engine API.

          It can either be a hex-encoded string or a file path to a file containing the hex-encoded secret.

          [env: BOLT_SIDECAR_ENGINE_JWT_HEX=]

      --fee-recipient <FEE_RECIPIENT>
          The fee recipient address for fallback blocks

          [env: BOLT_SIDECAR_FEE_RECIPIENT=]

      --builder-private-key <BUILDER_PRIVATE_KEY>
          Secret BLS key to sign fallback payloads with

          [env: BOLT_SIDECAR_BUILDER_PRIVATE_KEY=]

      --commitment-private-key <COMMITMENT_PRIVATE_KEY>
          Secret ECDSA key to sign commitment messages with. The public key associated to it must be then used when registering the operator in the `BoltManager` contract

          [env: BOLT_SIDECAR_COMMITMENT_PRIVATE_KEY=]

      --max-committed-gas-per-slot <MAX_COMMITTED_GAS_PER_SLOT>
          Max committed gas per slot

          [env: BOLT_SIDECAR_MAX_COMMITTED_GAS=]
          [default: 10000000]

      --min-inclusion-profit <MIN_INCLUSION_PROFIT>
          Min profit per gas to accept a commitment

          [env: BOLT_SIDECAR_MIN_PROFIT=]
          [default: 2000000000]

      --chain <CHAIN>
          Chain on which the sidecar is running

          [env: BOLT_SIDECAR_CHAIN=]
          [default: mainnet]
          [possible values: mainnet, holesky, helder, kurtosis]

      --commitment-deadline <COMMITMENT_DEADLINE>
          The deadline in the slot at which the sidecar will stop accepting new commitments for the next block (parsed as milliseconds)

          [env: BOLT_SIDECAR_COMMITMENT_DEADLINE=]
          [default: 8000]

      --slot-time <SLOT_TIME>
          The slot time duration in seconds. If provided, it overrides the default for the selected [Chain]

          [env: BOLT_SIDECAR_SLOT_TIME=]
          [default: 12]

      --constraint-private-key <CONSTRAINT_PRIVATE_KEY>
          Private key to use for signing constraint messages

          [env: BOLT_SIDECAR_CONSTRAINT_PRIVATE_KEY=]

      --commit-boost-signer-url <COMMIT_BOOST_SIGNER_URL>
          URL for the commit-boost sidecar

          [env: BOLT_SIDECAR_CB_SIGNER_URL=]

      --commit-boost-jwt-hex <COMMIT_BOOST_JWT_HEX>
          JWT in hexadecimal format for authenticating with the commit-boost service

          [env: BOLT_SIDECAR_CB_JWT_HEX=]

      --keystore-password <KEYSTORE_PASSWORD>
          The password for the ERC-2335 keystore. Reference: https://eips.ethereum.org/EIPS/eip-2335

          [env: BOLT_SIDECAR_KEYSTORE_PASSWORD=]

      --keystore-secrets-path <KEYSTORE_SECRETS_PATH>
          The path to the ERC-2335 keystore secret passwords Reference: https://eips.ethereum.org/EIPS/eip-2335

          [env: BOLT_SIDECAR_KEYSTORE_SECRETS_PATH=]

      --keystore-path <KEYSTORE_PATH>
          Path to the keystores folder. If not provided, the default path is used

          [env: BOLT_SIDECAR_KEYSTORE_PATH=]

      --delegations-path <DELEGATIONS_PATH>
          Path to the delegations file. If not provided, the default path is used

          [env: BOLT_SIDECAR_DELEGATIONS_PATH=]

      --metrics-port <METRICS_PORT>
          The port on which to expose Prometheus metrics

          [env: BOLT_SIDECAR_METRICS_PORT=]
          [default: 3300]

      --disable-metrics
          [env: BOLT_SIDECAR_DISABLE_METRICS=]

  -h, --help
          Print help (see a summary with '-h')

```

</details>

## Delegations and signing options for Native and Docker Compose Mode

As mentioned in the [prerequisites](#prerequisites) section, the Bolt sidecar
can sign commitments with an authorized set of private keys on behalf of active
Ethereum validators.

> [!IMPORTANT]
> This is the recommended way to run the Bolt sidecar as it
> doesn't expose the active validator signing keys to any additional risk.

In order to create these authorizations (delegations) you can use the `bolt` CLI binary.
If you don't want to use it you can skip the following section.

### `bolt` CLI

`bolt` CLI is an offline tool for safely generating delegation and revocation messages
signed with a BLS12-381 key for the [Constraints API][constraints-api]
in [Bolt][bolt].

The tool supports three key sources:

- **Secret Keys**: A list of BLS private keys provided directly as hex-strings.
- **Local Keystore**: A EIP-2335 keystore that contains an encrypted BLS private keys.
- **Dirk**: A remote Dirk server that provides the BLS signatures for the delegation messages.

and outputs a JSON file with the delegation/revocation messages to the provided
`<DELEGATEE_PUBKEY>` for the given chain.

#### Installation and usage

To install the bolt CLI, you can either use our pre-built binaries or build it from source.

**Using pre-built binaries**

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

**Building from source**

You will need the following dependencies to build the bolt CLI yourself:

- [Install Rust](https://www.rust-lang.org/tools/install)
- [Install Protoc](https://grpc.io/docs/protoc-installation/)

```bash
cd bolt-cli
cargo install --force --path .

# check for successful installation
bolt --help
```

Prerequisites:

- [Rust toolchain](https://www.rust-lang.org/tools/install)
- [Protoc](https://grpc.io/docs/protoc-installation/)

Once you have the necessary prerequisites, you can build the binary
in the following way:

```shell
# clone the Bolt repository if you haven't already
git clone git@github.com:chainbound/bolt.git

# navigate to the Bolt CLI package directory
cd bolt-cli

# build and install the binary on your machine
cargo install --path . --force

# test the installation
bolt --version
```

The binary can be used with the following command:

```shell
bolt delegate --delegatee-pubkey <DELEGATEE_PUBKEY>
              --out <OUTPUT_FILE>
              --chain <CHAIN>
              <KEY_SOURCE>
              <KEY_SOURCE_OPTIONS>
```

where:

- `<DELEGATEE_PUBKEY>` is the public key of the delegatee.
- `<OUTPUT_FILE>` is the path to the file where the delegation JSON messages will be written.
- `<CHAIN>` is the chain for which the delegations are being generated (e.g. Holesky).
- `<KEY_SOURCE>` is the key source to use for generating the delegations. It can be one of:
  - `secret-keys`: A list of BLS private keys provided directly as hex-strings.
  - `local-keystore`: A EIP-2335 keystore that contains an encrypted BLS private keys.
  - `dirk`: A remote Dirk server that provides the BLS signatures for the delegation messages.

You can also find more information about the available key source
options by running `bolt delegate <KEY_SOURCE> --help`.

Here you can see usage examples for each key source:

<details>
<summary>Usage</summary>

```text
❯ bolt-cli delegate --help
Generate BLS delegation or revocation messages
Usage: bolt-cli delegate [OPTIONS] --delegatee-pubkey <DELEGATEE_PUBKEY> <COMMAND>
Commands:
secret-keys     Use local secret keys to generate the signed messages
local-keystore  Use an EIP-2335 filesystem keystore directory to generate the signed messages
dirk            Use a remote DIRK keystore to generate the signed messages
help            Print this message or the help of the given subcommand(s)
Options:
    --delegatee-pubkey <DELEGATEE_PUBKEY>
        The BLS public key to which the delegation message should be signed
        [env: DELEGATEE_PUBKEY=]
    --out <OUT>
        The output file for the delegations
        [env: OUTPUT_FILE_PATH=]
        [default: delegations.json]
    --chain <CHAIN>
        The chain for which the delegation message is intended
        [env: CHAIN=]
        [default: mainnet]
        [possible values: mainnet, holesky, helder, kurtosis]
    --action <ACTION>
        The action to perform. The tool can be used to generate delegation or revocation messages (default: delegate)
        [env: ACTION=]
        [default: delegate]
        Possible values:
        - delegate: Create a delegation message
        - revoke:   Create a revocation message
-h, --help
        Print help (see a summary with '-h')
```

</details>

<details>
<summary>Examples</summary>

1. Generating a delegation using a local BLS secret key

```text
bolt-cli delegate \
  --delegatee-pubkey 0x8d0edf4fe9c80cd640220ca7a68a48efcbc56a13536d6b274bf3719befaffa13688ebee9f37414b3dddc8c7e77233ce8 \
  --chain holesky \
  secret-keys --secret-keys 642e0d33fde8968a48b5f560c1b20143eb82036c1aa6c7f4adc4beed919a22e3
```

2. Generating a delegation using an ERC-2335 keystore directory

```text
bolt-cli delegate \
 --delegatee-pubkey 0x8d0edf4fe9c80cd640220ca7a68a48efcbc56a13536d6b274bf3719befaffa13688ebee9f37414b3dddc8c7e77233ce8 \
 --chain holesky \
 local-keystore --path test_data/lighthouse/validators --password-path test_data/lighthouse/secrets
```

3. Generating a delegation using a remote DIRK keystore

```text
bolt-cli delegate \
  --delegatee-pubkey 0x83eeddfac5e60f8fe607ee8713efb8877c295ad9f8ca075f4d8f6f2ae241a30dd57f78f6f3863a9fe0d5b5db9d550b93 \
  dirk --url https://localhost:9091 \
  --client-cert-path ./test_data/dirk/client1.crt \
  --client-key-path ./test_data/dirk/client1.key \
  --ca-cert-path ./test_data/dirk/security/ca.crt \
  --wallet-path wallet1 --passphrases secret
```

</details>

<details>
<summary>Keystore-specific instructions</summary>

When using the `keystore` key source, the `--path` flag should point to the
directory containing the encrypted keypair directories.

The keystore folder must adhere to the following structure:

```text
${KEYSTORE_PATH}
|-- 0x81b676591b823270a3284ace7d81cbce2d6cdce55bb0e053874d7e3a08f729453009d3e662ec3130379f43c0f3210b6d
|   `-- voting-keystore.json
|-- 0x81ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb
|   `-- voting-keystore.json
|-- ...
    `-- ...
```

where the folder names are the public keys and inside every
folder there is a single JSON file containing the keystore file.

In case of validator-specific passwords (e.g. Lighthouse format) the
`--password-path` flag must be used instead of `--password`, pointing to the
directory containing the password files.

The passwords folder must adhere to a certain structure as well, as shown below.

```
${KEYSTORE_PATH}
|-- 0x81b676591b823270a3284ace7d81cbce2d6cdce55bb0e053874d7e3a08f729453009d3e662ec3130379f43c0f3210b6d
|-- 0x81ea9f74ef7d935b807474e38954ae3934856219a23e074954b2e860c5a3c400f9aedb42cd27cb4ceb697ca36d1e58cb
|-- ...
    `-- ...
```

That is, the password files should be named after the public key and each file
should just contain one line with the password in plain text. The files
themselves don't need a particular file extension.

</details>

---

Now that you have generated the delegation messages you can provide them to the
sidecar using the `--delegations-path` flag (or `BOLT_SIDECAR_DELEGATIONS_PATH`
env). When doing so the sidecar will check if they're indeed valid messages and
will keep in memory the association between the delegator and the delegatee.

However in order to sign the commitments you still need to provide the signing
key of the delegatee. There are two ways to do so, as explored in the sections
below.

### Using a private key directly

As you can see in the [command line options](#command-line-options) section you
can pass directly the private key as a hex-encoded string to the Bolt sidecar
using the `--constraint-private-key` flag (or
`BOLT_SIDECAR_CONSTRAINT_PRIVATE_KEY` env).

This is the simplest setup and can be used in case if all the delegations messages
point to the same delegatee or if you're running the sidecar with a single active
validator.

### Using a ERC-2335 Keystore

The Bolt sidecar supports [ERC-2335](https://eips.ethereum.org/EIPS/eip-2335)
keystores for loading signing keypairs. In order to use them you need to provide
the `--keystore-path` (`BOLT_SIDECAR_KEYSTORE_PATH` env) pointing to the folder
containing the keystore files and the `--keystore-password` or
`keystore-secrets-path` flag (`BOLT_SIDECAR_KEYSTORE_PASSWORD` or
`BOLT_SIDECAR_SECRETS_PATH` env respectively) pointing to the folder containing
the password file.

Both the `keys` and `passwords` folders must adhere to the structure outlined
in the [Installation and Usage](#installation-and-usage) section.

## Avoid restarting the beacon node

As mentioned in the [prerequisites](#prerequisites) section, in order to run the
sidecar correctly it might be necessary to restart your beacon client. That is
because you need to configure the `--builder` flag (or equivalent) to point to
the Bolt sidecar endpoint.

However if you're already running a PBS sidecar like
[MEV-Boost](https://boost.flashbots.net/) on the same machine then you can avoid
the restart by following this steps when starting the Bolt sidecar:

1. Set the `--constraints-proxy-port` flag (or
   `BOLT_SIDECAR_CONSTRAINTS_PROXY_PORT` env) to the port previously occupied by
   MEV-Boost.
2. Build the Bolt MEV-Boost fork binary or pull the Docker image and start it
   using another port
3. Set the `--constraints-api-url` flag (or `BOLT_SIDECAR_CONSTRAINTS_API_URL`
   env) to point to the Bolt MEV-Boost instance.

## Vouch configuration

If you are using [Vouch](https://www.attestant.io/posts/introducing-vouch/) as your validator client,
you will need to tweak its configuration to make sure that it doesn't fetch blocks from PBS relays directly,
otherwise your validators might propose a block that does not adhere to the signed constraints from the Bolt sidecar.

In particular, you'll need to point any external MEV relays to the sidecar URL.
Doing so can be done by tweaking the following configuration files:

#### `execution_config.json`

```json
{
  "version": 2,
  "fee_recipient": "<FEE_RECIPIENT_ADDRESS>",
  "relays": { "<BOLT_SIDECAR_CONSTRAINTS_API_URL>": {} },
  "proposers": []
}
```

Then using this config in `vouch.yaml`:

```yml
---
blockrelay:
  config:
    url: file:///data/vouch/execution_config.json
```
