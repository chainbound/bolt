# BOLT-CC (Bolt Credible Commitments)

Bolt-CC is a proof of concept for _permissionless proposer commitments through
PBS_. In its essence, it consists in a light fork of the current MEV-Boost
stack that allows users to request **preconfirmations** from proposers, and
then adds a way for proposers to commit to transaction inclusion in a way that
is easily verifiable.

## How it works

The flow of Bolt-CC can be summarized in the following steps:

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

## Scope of the PoC

This proof of concept aims to provide a working example of the flow depicted
above, proof generation and verification included, but it simplifies some parts
of the process to make it easier to implement in a devnet and to avoid
unnecessary complexity at this stage, such as:

- the preconfirmation request is made through a simple HTTP POST request
  directly to the proposer, as such it is exposed for direct traffic, which is
  not ideal in a production environment.
- the builder will place the preconfirmed transactions on the top of the block
  to ensure their validity

## Devnet and demo app

For this proof of concept, we are using a full
[Kurtosis](https://www.kurtosis.com/) devnet stack, with custom PBS docker images.
Additionally, this repo contains a simple web demo that allows to test the
whole preconfirmation flow.

### Requirements

Make sure you have the following:

- [Docker engine](https://docs.docker.com/engine/install/) installed and running
- [Kurtosis CLI](https://docs.kurtosis.com/install/) installed

### Running the devnet and demo

Running the devnet and demo is straightforward once you have the requirements
installed. Just run the following commands in your terminal:

```shell
# build all docker images locally first
make build-images

# spin up the kurtosis devnet on your machine
make up

# run the web demo servers.
make demo
```

The web demo will be available at [`http://localhost:3000`](http://localhost:3000).

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
