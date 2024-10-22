This document provides instructions for running the Bolt sidecar on the Holesky testnet.

# Table of Contents

<!-- vim-markdown-toc Marked -->

* [Prerequisites](#prerequisites)
* [Setup](#setup)
  * [Docker Mode (recommended)](#docker-mode-(recommended))
  * [Commit-Boost Mode](#commit-boost-mode)
  * [Native Mode (advanced)](#native-mode-(advanced))
    * [Building and running the MEV-Boost fork binary](#building-and-running-the-mev-boost-fork-binary)
    * [Building and running the Bolt sidecar binary](#building-and-running-the-bolt-sidecar-binary)
      * [Configuration file](#configuration-file)
    * [Observability](#observability)
* [Register your validators on-chain on the Bolt Registry](#register-your-validators-on-chain-on-the-bolt-registry)
  * [Validator Registration](#validator-registration)
  * [Bolt Network Entrypoint](#bolt-network-entrypoint)
    * [Symbiotic Integration guide for Staking Pools](#symbiotic-integration-guide-for-staking-pools)
    * [Symbiotic Integration guide for Operators](#symbiotic-integration-guide-for-operators)
    * [EigenLayer Integration Guide for Node Operators and Solo Stakers](#eigenlayer-integration-guide-for-node-operators-and-solo-stakers)
* [Reference](#reference)
  * [Command-line options](#command-line-options)
  * [Delegations and signing options for Native and Docker Compose Mode](#delegations-and-signing-options-for-native-and-docker-compose-mode)
    * [`bolt-delegations-cli`](#`bolt-delegations-cli`)
      * [Installation and usage](#installation-and-usage)
      * [Delegations CLI Example](#delegations-cli-example)
    * [Using a private key directly](#using-a-private-key-directly)
    * [Using a ERC-2335 Keystore](#using-a-erc-2335-keystore)
  * [Avoid restarting the beacon node](#avoid-restarting-the-beacon-node)

<!-- vim-markdown-toc -->

# Prerequisites

In order to run Bolt you need some components already installed and running in
your system.

**A synced Geth client:**

Bolt is fully trustless since it is able to produce a fallback block with the
commitments issued in case builders do not return a valid bid. In order to do so
it relies on a synced execution client, configured via the `--execution-api-url`
flag. At the moment only Geth is supported; with more
clients to be supported in the future.

Using the sidecar with a different execution client could lead to commitment
faults because fallback block building is not supported yet. You can download
Geth from [the official website](https://geth.ethereum.org/downloads).

**A synced beacon node:**

Bolt is compatible with every beacon client. Please refer to the various beacon
client implementations to download and run them.

> [!IMPORTANT]
> In order to correctly run the Bolt sidecar and avoid commitment faults the
> beacon node must be configured so that:
>
> 1. the node's `builder-api` (or equivalent flag) must point to the Bolt
>    Sidecar API.
> 2. the node will always prefer the builder payload. For instance, in
>    Lighthouse this can be achieved by providing the following flags:
>
>    ```text
>    --always-prefer-builder-payload
>    --builder-fallback-disable-checks
>    ```
>
> It might be necessary to restart your beacon node depending on your existing
> setup. See the [Avoid Restarting the Beacon
> Node](#avoid-restarting-the-beacon-node) for more details.

**Active validators:**

The Bolt sidecar requires signing keys from active Ethereum validators, or
authorized delegates acting on their behalf, to issue and sign preconfirmations.

**LST collateral:**

For Holesky in order to provide credible proposer commitments it is necessary to
restake 1 ether worth of ETH derivatives per validator in either the Symbiotic
or the EigenLayer protocol.

# Setup

There are various way to run the Bolt Sidecar depending on what infrastructure
you want to use and your preferred signing methods:

- Docker mode (recommended);
- [Commit-Boost](https://commit-boost.github.io/commit-boost-client) mode
  (requires Docker).
- Native mode (advanced, requires building everything from source);

Running the Bolt sidecar as a standalone binary requires building it from
source. Both the standalone binary and the Docker container requires reading
signing keys from [ERC-2335](https://eips.ethereum.org/EIPS/eip-2335) keystores,
while the Commit-Boost module relies on an internal signer and a custom PBS
module instead of regular [MEV-Boost](https://boost.flashbots.net/).

In this section we're going to explore each of these options and its
requirements.

## Docker Mode (recommended)

First, make sure to have both [Docker](https://docs.docker.com/engine/install/),
[Docker Compose](https://docs.docker.com/compose/install/) and
[git](https://git-scm.com/downloads) installed in your machine.

Then clone the Bolt repository by running:

```bash
git clone --branch v0.3.0 htts://github.com/chainbound/bolt.git && cd bolt
```

The Docker Compose setup will spin up the Bolt sidecar along with the Bolt
MEV-Boost fork which includes supports the [Constraints
API](https://docs.boltprotocol.xyz/api/builder).

Before starting the services, you'll need to provide configuration files
containing the necessary environment variables:

1. **Bolt Sidecar Configuration:**

   Create a `bolt-sidecar.toml` file in the `testnets/holesky` directory. If you
   need a reference, you can use the `Config.example.toml` file in the `bolt-sidecar`
   directory as a starting point.

   ```bash
   cp ./bolt-sidecar/Config.example.toml ./testnets/holesky/bolt-sidecar.toml
   ```

   For proper configuration of the signing
   options, please refer to the [Delegations and
   Signing](#delegations-and-signing-options-for-native-and-docker-compose-mode)
   section of this guide.

2. **MEV-Boost Configuration:**

   Similarly, create a `mev-boost.env` file in the
   `testnets/holesky` folder to configure the MEV-Boost service. If you need a
   reference, you can use the `.env.example` file in the `mev-boost` directory as a
   starting point.

   ```bash
   cp ./mev-boost/.env.example ./testnets/holesky/mev-boost.env
   ```

If you prefer not to restart your beacon node, follow the instructions in the
[Avoid Restarting the Beacon Node](#avoid-restarting-the-beacon-node) section.

Once the configuration files are in place, you can start the Docker containers
by running:

```bash
cd testnets/holesky && docker compose up -d
```

The docker compose setup comes with various observability tools, such as
Prometheus and Grafana. It also comes with some pre-built dashboards, which can
be found in the `grafana` directory.

## Commit-Boost Mode

First download the `commit-boost-cli` binary from the Commit-Boost [official
releases page](https://github.com/Commit-Boost/commit-boost-client/releases)

A commit-boost configuration file with Bolt support is provided at
[`cb-bolt-config.toml`](./cb-bolt-config.toml). This file has support for the
custom PBS module ([bolt-boost](../../bolt-boost)) that implements the
[constraints-API](https://chainbound.github.io/bolt-docs/api/builder), as well
as the [bolt-sidecar](../../bolt-sidecar) module. This file can be used as a
template for your own configuration.

The important fields to configure are under the `[modules.env]` section of the
`BOLT` module, which contain the environment variables to configure the bolt
sidecar:

```toml
[modules.env]
BOLT_SIDECAR_CHAIN = "holesky"

BOLT_SIDECAR_CONSTRAINTS_API = "http://cb_pbs:18550"     # The address of the PBS module (static)
BOLT_SIDECAR_BEACON_API = ""
BOLT_SIDECAR_EXECUTION_API = ""
BOLT_SIDECAR_ENGINE_API = ""                             # The execution layer engine API endpoint
BOLT_SIDECAR_JWT_HEX = ""                                # The engine JWT used to authenticate with the engine API
BOLT_SIDECAR_BUILDER_PROXY_PORT = "18551"                # The port on which the sidecar builder-API will listen on. This is what your beacon node should connect to.
BOLT_SIDECAR_FEE_RECIPIENT = ""                          # The fee recipient
BOLT_SIDECAR_VALIDATOR_INDEXES = ""                      # The active validator indexes (can be defined as a comma-separated list, or a range)
                                                         # e.g. "0,1,2,3,4" or "0..4", or a combination of both
```

To initialize commit-boost, run the following command:

```bash
commit-boost init --config cb-bolt-config.toml
```

This will create three files:

- `cb.docker-compose.yml`: which contains the full setup of the Commit-Boost services
- `.cb.env`: with local env variables, including JWTs for modules
- `target.json`: which enables dynamic discovery of services for metrics scraping via Prometheus

**Running**

The final step is to run the Commit-Boost services. This can be done with the following command:

```bash
commit-boost start --docker cb.docker-compose.yml --env .cb.env
```

This will run all modules in Docker containers.

> [!IMPORTANT]
> The `bolt-boost` service will be exposed at `pbs.port` (18551 by default, set
> with `BOLT_SIDECAR_BUILDER_PROXY_PORT`), and your beacon node MUST be
> configured to point the `builder-api` to this port for Bolt to work.

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
API](https://docs.boltprotocol.xyz/api/builder). This modified version is
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
cargo build --release && mv target/release/bolt-sidecar .
```

In order to run correctly the sidecar you need to provide either a list command
line options or a configuration file (recommended). All the options available
can be found by running `./bolt-sidecar --help`, or you can find them in the
[reference](#command-line-options) section of this guide.

#### Configuration file

You can use a `Config.toml` file to configure the sidecar, for which you can
find a template in the `Config.example.toml` file.
If you wish to place the configuration file in another folder you need to
specify the path of the configuration file by setting the
`BOLT_SIDECAR_CONFIG_PATH` environment variable to the path of the file.

Please read the section on [Delegations and Signing](#delegations-and-signing-options-for-native-and-docker-compose-mode)
to configure such sidecar options properly.

After you've set up the configuration file you can run the Bolt sidecar with

```bash
./bolt-sidecar-cli
```

### Observability

Commit-Boost comes with various observability tools, such as Prometheus,
cadvisor, and Grafana. It also comes with some pre-built dashboards, which can
be found in the `grafana` directory.

To update these dashboards, run the following command:

`bash ./update-grafana.sh `

In this directory, you can also find a Bolt dashboard, which will be launched
alongside the other dashboards.

# Register your validators on-chain on the Bolt Registry

Once you are successfully running the Bolt sidecar you need to register on-chain
on the Bolt Registry to successfully receive preconfirmation requests from users
and RPCs. This step is needed to provide economic security to your
commitments.

In order to do that you need some collateral in the form of whitelisted Liquid
Staking Token (LST) that needs to be restaked in either the Symbiotic or
EigenLayer protocol. Bolt is compatible with ETH derivatives on Holesky. Here
are references to the supported tokens on both restaking protocols:

- [Symbiotic Vaults](https://docs.symbiotic.fi/deployments#vaults)
  - [`wstETH`](https://holesky.etherscan.io/address/0x8d09a4502Cc8Cf1547aD300E066060D043f6982D)
  - [`rETH`](https://holesky.etherscan.io/address/0x7322c24752f79c05FFD1E2a6FCB97020C1C264F1)
- [EigenLayer Strategies](https://github.com/Layr-Labs/eigenlayer-contracts#current-testnet-deployment)
  - [`stETH`](https://holesky.etherscan.io/address/0x3F1c547b21f65e10480dE3ad8E19fAAC46C95034)
  - [`rETH`](https://holesky.etherscan.io/address/0x7322c24752f79c05FFD1E2a6FCB97020C1C264F1)
  - [`wETH`](https://holesky.etherscan.io/address/0x94373a4919B3240D86eA41593D5eBa789FEF3848)
  - [`cbETH`](https://holesky.etherscan.io/address/0x8720095Fa5739Ab051799211B146a2EEE4Dd8B37)
  - [`mETH`](https://holesky.etherscan.io/address/0xe3C063B1BEe9de02eb28352b55D49D85514C67FF)

Then you need to interact with two contracts on Holesky:
`BoltValidators` and `BoltManager`. The former is used to register your
active validators into the protocol, while the latter is used to manage to
register as an operator into the system and integrate with the restaking
protocols.

> [!IMPORTANT]
> When registering your operator in the `BoltManager` contract you must use the
> public key associated to the private key used to sign commitments with the
> Bolt Sidecar (the `--commitment-private-key` flag).

## Validator Registration

The [`BoltValidators`](./src/contracts/BoltValidators.sol) contract is the only point of entry for
validators to signal their intent to participate in Bolt Protocol and authenticate with their BLS private key.

The registration process includes the following steps:

1. Validator signs a message with their BLS private key. This is required to prove that the
   validator private key is under their control and that they are indeed its owner.
2. Validator calls the `registerValidator` function providing:
   1. Their BLS public key
   2. The BLS signature of the registration message
   3. The address of the authorized collateral provider
   4. The address of the authorized operator

Until the Pectra hard-fork will be activated, the contract will also expose a `registerValidatorUnsafe` function
that will not check the BLS signature. This is gated by a feature flag that will be turned off post-Pectra and
will allow us to test the registration flow in a controlled environment.

## Bolt Network Entrypoint

The [`BoltManager`](./src/contracts/BoltManager.sol) contract is a crucial component of Bolt that
integrates with restaking ecosystems Symbiotic and Eigenlayer. It manages the registration and
coordination of validators, operators, and vaults within the Bolt network.

Key features include:

1. Retrieval of operator stake and proposer status from their pubkey
2. Integration with Symbiotic
3. Integration with Eigenlayer

Specific functionalities about the restaking protocols are handled inside
the `IBoltMiddleware` contracts, such as `BoltSymbioticMiddleware` and `BoltEigenlayerMiddleware`.

### Symbiotic Integration guide for Staking Pools

As a staking pool, it is assumed that you are already in control of a Symbiotic Vault.
If not, please refer to the [Symbiotic docs](https://docs.symbiotic.fi/handbooks/Handbook%20for%20Vaults)
on how to spin up a Vault and start receiving stake from your node operators.

Opting into Bolt works as any other Symbiotic middleware integration. Here are the steps:

1. Make sure your vault collateral is whitelisted in `BoltSymbioticMiddleware` by calling `isCollateralWhitelisted`.
2. Register as a vault in `BoltSymbioticMiddleware` by calling `registerVault`.
3. Verify that your vault is active in `BoltSymbioticMiddleware` by calling `isVaultEnabled`.
4. Set the network limit for your vault in Symbiotic with `Vault.delegator().setNetworkLimit()`.
5. You can now start approving operators that opt in to your vault directly in Symbiotic.
6. When you assign shares to operators, they are able to provide commitments on behalf of your collateral.

### Symbiotic Integration guide for Operators

As an operator, you will need to opt-in to the Bolt Network and any Vault that trusts you to provide
commitments on their behalf.

The opt-in process requires the following steps:

1. register in Symbiotic with `OperatorRegistry.registerOperator()`.
2. opt-in to the Bolt network with `OperatorNetworkOptInService.optIn(networkAddress)`.
3. opt-in to any vault with `OperatorVaultOptInService.optIn(vaultAddress)`.
4. register in Bolt with `BoltSymbioticMiddleware.registerOperator(operatorAddress)`.
5. get approved by the vault.
6. start providing commitments with the stake provided by the vault.

### EigenLayer Integration Guide for Node Operators and Solo Stakers

> [!NOTE]
> Without loss of generality, we will assume the reader of this guide is a Node
> Operator (NO), since the same steps apply to solo stakers.
> As a Node Operator you will be an ["Operator"](https://docs.eigenlayer.xyz/eigenlayer/overview/key-terms)
> in the Bolt AVS built on top of EigenLayer. This requires
> running an Ethereum validator and the Bolt sidecar in order issue
> preconfirmations.

The Operator will be represented by an Ethereum address that needs
to follow the standard procedure outlined in the
[EigenLayer documentation](https://docs.eigenlayer.xyz/) to opt into EigenLayer. Let's go through the steps:

1. As an Operator, you register into EigenLayer using [`DelegationManager.registerAsOperator`](https://github.com/Layr-Labs/eigenlayer-contracts/blob/mainnet/src/contracts/core/DelegationManager.sol#L107-L119).

2. As an Ethereum validator offering precofirmations a NO needs some collateral in
   order to be economically credible. In order to do that, some entities known as a "stakers"
   need to deposit whitelisted Liquid Staking Tokens (LSTs)
   into an appropriate "Strategy" associated to the LST via the
   [`StrategyManager.depositIntoStrategy`](https://github.com/Layr-Labs/eigenlayer-contracts/blob/mainnet/src/contracts/core/StrategyManager.sol#L105-L110),
   so that the Operator has a `min_amount` (for Holesky 1 ether) of collateral associated to it.
   Whitelisted LSTs are exposed by the `BoltEigenLayerMiddleware` contract
   in the `getWhitelistedCollaterals` function.
   Note that NOs and stakers can be two different entities
   _but there is fully trusted relationship as stakers will be slashed if a NO misbehaves_.

3. After the stakers have deposited their collateral into a strategy they need
   to choose you as their operator. To do that, they need to call the function
   [`DelegationManager.delegateTo`](https://github.com/Layr-Labs/eigenlayer-contracts/blob/mainnet/src/contracts/core/DelegationManager.sol#L154-L163).

4. As an Operator you finally opt into the Bolt AVS by interacting with the `BoltEigenLayerMiddleware`.
   This consists in calling the function `BoltEigenLayerMiddleware.registerOperatorToAVS`.
   The payload is a signature whose digest consists of:

   1. your operator address
   2. the `BoltEigenLayerMiddleware` contract address
   3. a salt
   4. an expiry 2.

   The contract will then forward the call to the [`AVSDirectory.registerOperatorToAVS`](https://github.com/Layr-Labs/eigenlayer-contracts/blob/mainnet/src/contracts/core/AVSDirectory.sol#L64-L108)
   with the `msg.sender` set to the Bolt AVS contract. Upon successful verification of the signature,
   the operator is considered `REGISTERED` in a mapping `avsOperatorStatus[msg.sender][operator]`.

Lastly, a NO needs to interact with both the `BoltValidators` and `BoltEigenLayerMiddleware`
contract. This is needed for internal functioning of the AVS and to make RPCs aware that you are a
registered operator and so that they can forward you preconfirmation requests.

The steps required are the following:

1. Register all the validator public keys you want to use with Bolt via the `BoltValidators.registerValidator`.
   If you own more than one validator public key,
   you can use the more gas-efficient `BoltValidators.batchRegisterValidators` function.
   The `authorizedOperator` argument must be the same Ethereum address used for
   opting into EigenLayer as an Operator.

2. Register the same Operator address in the `BoltEigenLayerMiddleware` contract by calling
   the `BoltEigenLayerMiddleware.registerOperator` function. This formalizes your role within the Bolt network
   and allows you to manage operations effectively, such as pausing or resuming
   your service.

3. Register the EigenLayer strategy you are using for restaking _if it has not been done by someone else already_.
   This ensures that your restaked assets are correctly integrated with Bolt’s system.

# Reference

## Command-line options

For completeness, here are all the command-line options available for the Bolt
sidecar. You can see them in your terminal by running the Bolt sidecar binary
with the `--help` flag:

```
Command-line options for the Bolt sidecar

Usage: bolt-sidecar [OPTIONS] --validator-indexes <VALIDATOR_INDEXES> --engine-jwt-hex <ENGINE_JWT_HEX> --fee-recipient <FEE_RECIPIENT> --builder-private-key <BUILDER_PRIVATE_KEY> --commitment-private-key <COMMITMENT_PRIVATE_KEY> <--constraint-private-key <CONSTRAINT_PRIVATE_KEY>|--commit-boost-signer-url <COMMIT_BOOST_SIGNER_URL>|--keystore-password <KEYSTORE_PASSWORD>|--keystore-secrets-path <KEYSTORE_SECRETS_PATH>>

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

      --validator-indexes <VALIDATOR_INDEXES>
          Validator indexes of connected validators that the sidecar should accept commitments on behalf of. Accepted values: - a comma-separated list of indexes (e.g. "1,2,3,4") - a contiguous range of indexes (e.g. "1..4") - a mix of the
          above (e.g. "1,2..4,6..8")

          [env: BOLT_SIDECAR_VALIDATOR_INDEXES=]

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

      --max-commitments-per-slot <MAX_COMMITMENTS_PER_SLOT>
          Max number of commitments to accept per block

          [env: BOLT_SIDECAR_MAX_COMMITMENTS=]
          [default: 128]

      --max-committed-gas-per-slot <MAX_COMMITTED_GAS_PER_SLOT>
          Max committed gas per slot

          [env: BOLT_SIDECAR_MAX_COMMITTED_GAS=]
          [default: 10000000]

      --min-priority-fee <MIN_PRIORITY_FEE>
          Min priority fee to accept for a commitment

          [env: BOLT_SIDECAR_MIN_PRIORITY_FEE=]
          [default: 1000000000]

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

## Delegations and signing options for Native and Docker Compose Mode

As mentioned in the [prerequisites](#prerequisites) section, the Bolt sidecar
can sign commitments with a delegated set of private keys on behalf of active
Ethereum validators.

> [!IMPORTANT]
> This is the recommended way to run the Bolt sidecar as it
> doesn't expose the active validator signing keys to any additional risk.

In order to create these delegation you can use the `bolt-delegations-cli` binary.
If you don't want to use it you can skip the following section.

### `bolt-delegations-cli`

`bolt-delegations-cli` is an offline command-line tool for safely generating
delegation and revocation messages signed with a BLS12-381 key for the
[Constraints API](https://docs.boltprotocol.xyz/api/builder) in
[Bolt](https://docs.boltprotocol.xyz/).

The tool supports two key sources:

- Local: A BLS private key provided directly from a file.
- Keystore: A keystore file that contains an encrypted BLS private key.

and outputs a JSON file with the delegation/revocation messages to the provided
`<DELEGATEE_PUBKEY>` for the given chain

Features:

- Offline usage: Safely generate delegation messages in an offline environment.
- Flexible key source: Support for both direct local BLS private keys and
  Ethereum keystore files (ERC-2335 format).
- BLS delegation signing: Sign delegation messages using a BLS secret key and
  output the signed delegation in JSON format.

#### Installation and usage

Go to the root of the Bolt project you've previously cloned using Git. Enter in
the `bolt-delegations-cli` directory by running `cd bolt-delegations-cli`.

If you're using the Docker container setup make sure you have
[Rust](https://www.rust-lang.org/tools/install) installed in your system as
well. Then you can build the `bolt-delegations-cli` binary by running:

```bash
cargo build --release && mv target/release/bolt-delegations-cli .
```

Now you can run the binary by running:

```bash
./bolt-delegations-cli <COMMAND>
```

The binary exposes a single `generate` command, which accepts the following
options and subcommands (use `./bolt-delegations-cli generate --help` to see
them):

```text
Usage: bolt-delegations-cli generate [OPTIONS] --delegatee-pubkey <DELEGATEE_PUBKEY> <COMMAND>

Commands:
  local     Use local private keys to generate the signed messages
  keystore  Use an EIP-2335 keystore folder to generate the signed messages
  help      Print this message or the help of the given subcommand(s)

Options:
      --delegatee-pubkey <DELEGATEE_PUBKEY>  The BLS public key to which the delegation message should be signed [env: DELEGATEE_PUBKEY=]
      --out <OUT>                            The output file for the delegations [env: OUTPUT_FILE_PATH=] [default: delegations.json]
      --chain <CHAIN>                        The chain for which the delegation message is intended [env: CHAIN=] [default: mainnet] [possible values: mainnet, holesky, helder, kurtosis]
      --action <ACTION>                      The action to perform. The tool can be used to generate delegation or revocation messages (default: delegate) [env: ACTION=] [default: delegate] [possible values: delegate, revoke]
  -h, --help                                 Print help (see more with '--help')
```

> [!TIP]
> If you're using the Docker Compose Mode please don't set the `--out` flag and
> provide `delegations_path = /etc/delegations.json` in the `bolt-sidecar.toml`
> file.

The environment variables can be also set in a `.env` file. For a reference
example you can check out the `.env.local.example` and the
`.env.keystore.example`

In the section below you can see a usage example of the binary.

#### Delegations CLI Example

1. Using a local BLS private key:

   ```text
   bolt-delegations-cli generate \
       --delegatee-pubkey 0x7890ab... \
       --out my_delegations.json \
       --chain holesky \
       local \
       --secret-keys 0xabc123...,0xdef456..
   ```

2. Using a Ethereum keystores files and raw password:

   ```text
   bolt-delegations-cli generate \
       --delegatee-pubkey 0x7890ab... \
       --out my_delegations.json \
       --chain holesky \
       keystore \
       --path /keys \
       --password myS3cr3tP@ssw0rd
   ```

3. Using an Ethereum keystores files and secrets folder

   ```text
   bolt-delegations-cli generate \
       --delegatee-pubkey 0x7890ab... \
       --out my_delegations.json \
       --chain holesky \
       keystore \
       --path /keys \
       --password-path /secrets
   ```

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

---

Now that you have generated the delegation messages you can provide them to the
sidecar using the `--delegations-path` flag (see the
[options](#command-line-options) section). When doing so the sidecar will check if
they're indeed valid messages and will keep in memory the association between
the delegator and the delegatee.

However in order to sign the commitments you still need to provide the signing
key of the delegatee. There are two ways to do so, as explored in the sections
below.

### Using a private key directly

As you can see in the [command line options](#command-line-options) section you
can pass directly the private key as a hex-encoded string to the Bolt sidecar
using the `--private-key` flag. This is the simplest setup and can be used in
case if all the delegations messages point to the same delegatee or if you're
running the sidecar with a single active validator.

### Using a ERC-2335 Keystore

The Bolt sidecar supports [ERC-2335](https://eips.ethereum.org/EIPS/eip-2335) keystores for loading signing keypairs.
In order to use them you need to provide the `--keystore-path` pointing to the
folder containing the keystore files and the `--keystore-password` or
`keystore-secrets-path` flag pointing to the folder containing the password
file.

Both the `keys` and `passwords` folders must adhere to the structure outlined
in the [Delegations CLI example](#delegations-cli-example) section.

## Avoid restarting the beacon node

As mentioned in the [prerequisites](#prerequisites) section, in order to run the
sidecar correctly it might be necessary to restart your beacon client. That is
because you need to configure the `--builder` flag (or equivalent) to point to
the Bolt sidecar endpoint.

However if you're already running a PBS sidecar like
[MEV-Boost](https://boost.flashbots.net/) on the same machine then you can avoid
the restart by following this steps when starting the Bolt sidecar:

1. Set the `--constraints-proxy-port` flag or the
   `BOLT_SIDECAR_BUILDER_PROXY_PORT` environment variable to the port previously occupied by
   MEV-Boost.
2. Build the Bolt MEV-Boost fork binary or pull the Docker image and start it
   using another port
3. Set the `--constraints-url` flag or the `BOLT_SIDECAR_CONSTRAINTS_URL` to point to the Bolt MEV-Boost instance.
