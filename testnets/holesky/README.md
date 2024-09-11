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
cargo install --locked --git https://github.com/Commit-Boost/commit-boost-client --rev 45ce8f1 commit-boost

# Test installation
commit-boost --version
```
#### Configuration
A commit-boost configuration file with Bolt support is provided at [`cb-bolt-config.toml`](./cb-bolt-config.toml). This file has support
for the custom PBS module ([bolt-boost](../../bolt-boost)) that implements the [constraints-API](https://chainbound.github.io/bolt-docs/api/builder), as
well as the [bolt-sidecar](../../bolt-sidecar) module. This file can be used as a template for your own configuration.

To initialize commit-boost, run the following command:
```bash
commit-boost init --config cb-bolt-config.toml
```

This will create 3 files:
- `cb.docker-compose.yml`: which contains the full setup of the Commit-Boost services
- `.cb.env`: with local env variables, including JWTs for modules
- `target.json`: which enables dynamic discovery of services for metrics scraping via Prometheus, only created if metrics are enabled

#### Running
The final step is to run the Commit-Boost services. This can be done with the following command:
```bash
commit-boost start --docker cb.docker-compose.yml --env .cb.env
```
This will run all modules in Docker containers.

> [!IMPORTANT]
> bolt-boost will be exposed at `pbs.port` (18550 by default), and your beacon node MUST be configured
> to point the `builder-api` to this port for Bolt to work.

### Bolt Sidecar
Your sidecar

### Validators
Validators must be configured to always prefer builder proposals over their own. Refer to client documentation for the specific configuration flags.
**If this is not set, it could lead to commitment faults**.

#### Registration
