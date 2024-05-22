# BOLT

<!-- vim-markdown-toc Marked -->

- [How it works](#how-it-works)
- [Scope of this repository](#scope-of-this-repository)
- [Devnet and demo app](#devnet-and-demo-app)
  - [Requirements](#requirements)
  - [Running the devnet and demo](#running-the-devnet-and-demo)
  - [Stopping the devnet and demo](#stopping-the-devnet-and-demo)
- [Changelog](#changelog)
  - [Bolt Sidecar](#bolt-sidecar)
  - [Builder](#builder)
  - [Relay](#relay)
  - [MEV-Boost](#mev-boost)

<!-- vim-markdown-toc -->

> [!IMPORTANT]
> Bolt is an implementation of _permissionless proposer commitments through
> PBS_. In its essence, it consists in a light fork of the current MEV-Boost
> stack that allows users to request **preconfirmations** from proposers, and
> then adds a way for proposers to commit to transaction inclusion in a way that
> is easily verifiable.

## How it works

The flow of Bolt can be summarized in the following steps:

1. Users submit transactions to the proposer next in line
2. The proposer can accept this transaction, and after that it will send a
   preconfirmation to the user and the constraint to the relays.
3. Builders pull the list of preconfirmed transactions from
   the relays
4. Builders build valid blocks with the preconfirmations and append a proof of
   inclusion with their bids
5. Relays can then forward these proofs to the proposers when the
   `getHeader` request is made
6. The proposer now has all the necessary info to verify if the payload
   includes the preconfirmations
7. If the block is valid, the proposer can propose it as usual. If not, the
   proposer can self-build it.

A diagram of this flow is available [here](https://swimlanes.io/u/hwwDL7z1P)

## Scope of this repository

This proof of concept aims to provide a working example of the flow depicted
above, proof generation and verification included, but it simplifies some parts
of the process to make it easier to implement in a devnet and to avoid
unnecessary complexity at this stage, such as:

- the builder will place the preconfirmed transactions on the top of the block
  to ensure their validity. In a real scenario, builders would adapt their bundle
  merging algorithms to place the preconfirmed transactions where they fit best.
- the relay doesn't ensure to store bids with valid proofs of inclusion. In a
  production environment this should be done to forward only valid bids to the
  proposer and minimize the risk of falling back to a locally built block.
- the fallback logic to a locally built block is simplified.

## Devnet and demo app

We are using a full [Kurtosis](https://www.kurtosis.com/) devnet stack, with
custom PBS docker images. Additionally, this repo contains a simple web demo
that allows us to test the whole preconfirmation flow.

End-to-end test scenarios are also available as playgrounds to showcase
different fault scenarios and how the system behaves.

### Requirements

Make sure you have the following requirements on your machine:

- [Docker engine](https://docs.docker.com/engine/install/) installed and running
- [Kurtosis CLI](https://docs.kurtosis.com/install/) installed
- [Foundry](https://book.getfoundry.sh/getting-started/installation) installed

Then, clone this repository and navigate to the root directory of the project:

```shell
git clone git@github.com:chainbound/bolt.git && cd bolt
```

### Running the devnet and demo

Running the devnet and demo is straightforward once you have the requirements
installed. Just run the following commands in your terminal:

```shell
# build all necessary docker images locally first
make build-images

# spin up the kurtosis devnet on your machine
make up

# run the web demo servers.
make demo
```

The web demo will be available on your browser at
[`http://localhost:3000`](http://localhost:3000).

### Stopping the devnet and demo

The demo app will remain open until you press `Ctrl+C` in the terminal where
you ran the `make demo` command.

To stop the devnet, run the following command:

```shell
# if you want to simply stop all running containers
make down

# if you want to remove all the data and stop the Kurtosis engine
make clean
```

> [!WARNING]
> Remember to shut down the devnet environment when you are done with it, as it
> consumes significant resources on your machine :)

## Changelog

All notable changes to the components of this project will be documented here.

### Bolt Sidecar

The sidecar is responsible for handling the preconfirmation requests from the
user via JSON-RPC, and forward them to the relay.

**Added**

- `eth_requestPreconfirmation` whose params are a RLP-encoded `rawTx` and the `slot`
  for which the preconfirmation is requested.
- `eth_getPreconfirmation` which returns the preconfirmation accepted by the
  proposer for the given `slot`.

### Builder

The outlined changes refer to the implementation of the [builder made by
the Flashbots team](https://github.com/flashbots/builder/tree/v1.13.14-0.3.0). In order to
best comprehend the changes it is recommended to keep [Flashbots' builder flow
diagram](https://github.com/flashbots/builder/blob/v1.13.14-0.3.0/docs/builder/builder-diagram.png)
at hand.

The PR implementing the changes can be found [here](https://github.com/chainbound/bolt-v0/pull/9).

**Added**

- Utility to pull preconfirmed transactions from the relay
- Utility to generate the SSZ hash tree root of a transaction
- Utility to generate a Merkle proof of inclusion of at a certain index
  in the SSZ list of transactions

**Changed**

- Fetch preconfirmed transactions when running building job
  (`runBuildingJob`) using the sidecar/relay endpoint `eth_getPreconfirmation`
- Preconfirmed transactions are propagated downstream in the building pipeline,
  and injected as part of the mempool when the block filling process begins
  (`fillTrasanctionsAlgoWorker`)
- Generate Merkle proofs of inclusions for the preconfirmed transactions when the block is sealed
  (`onSealedBlock`) and the bid is ready to be sent to the relay
- Builder bid is sent to a new relay endpoint `/relay/v1/builder/blocks_with_preconfs`
  along with the proofs

### Relay

The outlined changes refer to the implementation of the [relay made by the
Flashbots team](https://github.com/flashbots/mev-boost-relay/tree/v0.29.1).

The PR implementing the changes can be found
[here](https://github.com/chainbound/bolt-v0/pull/10).

**Added**

- New endpoint `/relay/v1/builder/blocks_with_preconfs` to receive builder
  bids with preconfirmed transactions and their Merkle proofs of inclusion.
  This endpoint doesn't accept SSZ encoded content, only JSON for now.
- New Redis cache key `cache-preconfirmations-proofs` to store Merkle proofs

### MEV-Boost

The outlined changes refer to the implementation of the [MEV-Boost made by the
Flashbots team](https://github.com/flashbots/mev-boost/tree/v1.7).

The PR implementing the changes can be found [here](https://github.com/chainbound/bolt-v0/pull/11)

**Added**

- Utility to generate the SSZ hash tree root of a transaction and to verify a
  Merkle proof of inclusion

**Changed**

- The `getHeader` endpoint verifies the Merkle proofs if expected, and rejects the bid if not valid
