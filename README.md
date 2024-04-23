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

## Run the devnet

For this proof of concept, we are using a full [Kurtosis](https://www.kurtosis.com/) devnet stack, with custom PBS images. 
To run the devnet, you can use the following commands:

```shell
# build all docker images locally first (this will take a while)
make build-images

# spin up the kurtosis devnet
make up
```

and to stop it:

```shell
# stop and remove the kurtosis enclave
make down

# clean up artifacts and stop the kurtosis engine
make clean
```

