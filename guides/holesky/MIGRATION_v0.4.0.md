# `v0.4.0-alpha` Migration Guide

This document outlines a migration guide for upgrading bolt to v0.4.0-alpha, which contains some breaking changes. We'll start with an overview of the main changes.

- [Firewall delegation](#firewall-delegation)
- [New pricing model](#new-pricing-model)
- [**Required action**](#required-action)

### Firewall delegation

Firewall delegation allows proposers to set an external third party as their network entrypoint or _firewall_. It gets rid of the
requirement to expose an HTTP RPC endpoint for accepting inclusion requests (inbound), and instead subscribes to the configured firewall over a
websocket connection (outbound). The firewall will then stream valid, filtered inclusion requests over the websocket connection.

Some of the other duties of the firewall include:

- Spam and DoS prevention
- Pricing inclusion requests correctly (see more below)
- Communicating prices with consumers (wallets, users)

Currently, we operate a firewall RPC on Holesky at `wss://rpc.holesky.boltprotocol.xyz/api/v1/firewall_stream`.

Read more about firewall delegation [here](https://x.com/boltprotocol_/status/1879571451621077413).

### New pricing model

This new release also comes with an upgraded, dynamic pricing model that's based on joint research by Nethermind and Chainbound.
The model is described in [this post](https://research.lido.fi/t/a-pricing-model-for-inclusion-preconfirmations/9136). In short,
it provides an estimate for the floor price an inclusion preconfirmation MUST have so that the proposer has a very minimal chance of
losing revenue by committing to it.

Our model varies slightly from the original description due to implementation details, which we'll cover in another document. Additionally,
the bolt-sidecar allows proposers to configure a **minimum profit** parameter that is added to the floor price in order to arrive at a total
priority fee.

Check out all release notes [here](https://github.com/chainbound/bolt/releases/tag/v0.4.0-alpha).

### Required action

Start by pulling in the changes:

```bash
# Optional
git clone --branch v0.4.0-alpha https://github.com/chainbound/bolt

# OR in your local repo
git pull && git checkout v0.4.0-alpha

# Navigate to the holesky directory
cd bolt/guides/holesky
```

Also download the latest version of the bolt CLI:

```bash
# download the bolt-cli installer
curl -L https://raw.githubusercontent.com/chainbound/bolt/unstable/boltup/install.sh | bash

# start a new shell to use the boltup installer
exec $SHELL

# install latest bolt-cli binary
boltup --tag v0.1.2

# check for successful installation
bolt --help
```

These changes are quite substantial, as they contain updated docker compose files & container versions, along with updated
configs. **All of the changes outlined below are in `bolt-sidecar.env` (`mev-boost.env` remains unchanged)**.

##### Firewall delegation

- `BOLT_SIDECAR_FIREWALL_RPCS` configures the sidecar to run in firewall delegation mode with the provided endpoint. This option is set by default in the presets.
- `BOLT_SIDECAR_PORT` controls whether to expose an HTTP endpoint instead of using firewall delegation. These 2 options are mutually exclusive.

> [!IMPORTANT]
> To fully enable firewall delegation, you must modify your
> on-chain operator RPC and set it to the following RPC: `https://rpc.holesky.boltprotocol.xyz/rpc`.
> You can do this by running the following bolt CLI command (required version v0.1.2):
>
> ```bash
> bolt operators eigenlayer update-rpc https://rpc.holesky.boltprotocol.xyz/rpc
> # OR
> bolt operators symbiotic update-rpc https://rpc.holesky.boltprotocol.xyz/rpc
> ```

##### Pricing

- `BOLT_SIDECAR_MIN_PRIORITY_FEE` has been replaced by `BOLT_SIDECAR_MIN_PROFIT`, which is the amount of gwei
  added to the floor price determined by the pricing model

##### Other

- `BOLT_SIDECAR_COMMITMENT_PRIVATE_KEY` has been renamed to `BOLT_SIDECAR_OPERATOR_PRIVATE_KEY`
- `BOLT_SIDECAR_MAX_COMMITMENTS_PER_SLOT` has been dropped, `BOLT_SIDECAR_MAX_COMMITTED_GAS` remains

These configuration values are present in [`bolt-sidecar.env.example`](./bolt-sidecar.env.example) or in [`sidecar-delegations-preset.env.example`](./presets/sidecar-delegations-preset.env.example). You can either copy those and update them to your required values,
or modify your existing config.

##### Config guidelines

- Don't set `BOLT_SIDECAR_MIN_PROFIT` to something too high (2 gwei will work for now), or our simulated transaction sender might not send you any inclusion requests.
- You can set `BOLT_SIDECAR_MAX_COMMITTED_GAS` to any value smaller than the block gas limit. We recommend no higher than `20_000_000` on Holesky. This parameter controls the maximum amount of gas per slot you're willing to reserve for commitments.
- If you're using firewall delegation (the default), you can remove any local firewall rules related to the Bolt public HTTP endpoint.
