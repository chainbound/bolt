# Holesky Launch Instructions

## Components

The components that need to run to test Bolt on Holesky are:

- A synced execution client
- A synced beacon node
- Active validators
- Commit-Boost with Bolt configuration

## Setup

### Commit-Boost

#### Installation

To install the `commit-boost` CLI with `cargo`:

```bash
# Use specific commit hash to ensure compatibility
cargo install --locked --git https://github.com/Commit-Boost/commit-boost-client --rev aed00e8 commit-boost

# Test installation
commit-boost --version
```

#### Configuration

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

This will create 3 files:

- `cb.docker-compose.yml`: which contains the full setup of the Commit-Boost services
- `.cb.env`: with local env variables, including JWTs for modules
- `target.json`: which enables dynamic discovery of services for metrics scraping via Prometheus

#### Running

The final step is to run the Commit-Boost services. This can be done with the following command:

```bash
commit-boost start --docker cb.docker-compose.yml --env .cb.env
```

This will run all modules in Docker containers.

> [!IMPORTANT]
> bolt-boost will be exposed at `pbs.port` (18551 by default, set with `BOLT_SIDECAR_BUILDER_PROXY_PORT`), and your beacon node MUST be configured
> to point the `builder-api` to this port for Bolt to work.

### Bolt Sidecar

WIP

### Observability

commit-boost comes with various observability tools, such as Prometheus, cadvisor, and Grafana. It also comes with some pre-built dashboards,
which can be found in the `grafana` directory.

To update these dashboards, run the following command:

```bash
./update-grafana.sh
```

In this directory, you can also find a Bolt dashboard, which will be launched alongside the other dashboards.

### Validators

Validators must be configured to always prefer builder proposals over their own. Refer to client documentation for the specific configuration flags.
**If this is not set, it could lead to commitment faults**.

#### Registration

WIP
