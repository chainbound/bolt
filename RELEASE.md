# Guide on creating new releases

## 0. Pre-release checks

There is not a single end2end test procedure, but each release should at least
go through a manual test of the core components, including the happy-case and
error-case scenarios. This includes the Kurtosis devnet environment and any
live testnet deployment that is available at time of release.

For testnets, if the launch setup has changed since the previous version,
the `testnets/` directory should be updated to reflect the new setup.
Pay special attention to the `README` and `docker-compose` files.

## 1. Update the version tag in the necessary packages

For instance, for the Bolt sidecar this is in `bolt-sidecar/Cargo.toml`.
Similar changes should be made in the other packages getting updated.

We don't currently keep track of the version for flashbots forks.

Next, update the version of the Docker images used in any `docker-compose` files.
These currently only live inside the `testnets/` dir.

## 2. Create a release on Github

Create a new release on Github with the new tag and a description of the changes.

We use the built-in Github changelog feature to generate the changelog.

## 3. Build new Docker images

You can build new Docker images with the `just release <tag>` recipe.

Example: `just release v0.2.0-alpha` will build and push the Docker images
for all Bolt components with the tag `v0.2.0-alpha` for both `arm64` and `amd64`
architectures. This can take a long time... We recommend building from an ARM machine
because cross-compiling from x86 into ARM is slow as hell.
