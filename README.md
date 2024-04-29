# BOLT

Bolt is a proof of concept for _permissionless proposer commitments through PBS_. In its essence, it consists in a light fork of the current Mev-boost stack that allows users to request **preconfirmations** from proposers, and then adds a way for proposers to commit to transaction inclusion in a way that is easily verifiable.

## How it works

1. Users submit transactions to the proposer next in line (^1)
2. The proposer can accept this transaction, and send a preconfirmation to the user
3. The PBS builders can then request the list of preconfirmed transactions from the proposer
4. Builders build valid blocks with the preconfirmations and append a proof of inclusion with their bids
5. The relays can then forward these proofs to the proposers when the `getHeader` request is made
6. The proposer now has all the necessary info to verify if the payload includes the preconfirmations
7. If the block is valid, the proposer can propose it as usual. If not, the proposer can self-build

(^1) This is a simplification for the sake of the proof of concept. In production, it's not ideal to have proposers expose an endpoint and accept direct traffic. We are planning to use a distributed relay network to handle parts of the communication and pricing of the preconfirmations.

## Devnet and demo app

For this proof of concept, we are using a full [Kurtosis](https://www.kurtosis.com/) devnet stack, with custom PBS images.
Additionally, this repo contains a simple web demo that allows to test the whole preconfirmation flow.

### Requirements

Make sure you have the following:

- [Docker engine](https://docs.docker.com/engine/install/) installed and running
- [Kurtosis CLI](https://docs.kurtosis.com/install/) installed

### Running the devnet and demo

Running the devnet and demo is straightforward once you have the requirements installed.
Just run the following commands in your terminal:

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

The demo app will remain open until you press `Ctrl+C` in the terminal where you ran the `make demo` command.

To stop the devnet, run the following command:

```shell
# if you want to simply stop all running containers
make down

# if you want to remove all the data and stop the Kurtosis engine
make clean
```
