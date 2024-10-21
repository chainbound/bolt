#!/bin/sh

geth --datadir=/var/lib/chaindata/geth \
        --holesky \
        --syncmode=full \
        --gcmode=archive \
        --state.scheme=hash \
        --verbosity=3 \
        --http \
        --http.port=8545 \
        --http.addr=0.0.0.0 \
        --http.vhosts=* \
        --http.corsdomain=* \
        --http.api=admin,engine,net,eth,web3,debug,flashbots,txpool \
        --ws \
        --ws.addr=0.0.0.0 \
        --ws.port=8546 \
        --ws.api=admin,engine,net,eth,web3,debug,flashbots,txpool \
        --ws.origins=* \
        --authrpc.port=8551 \
        --authrpc.addr=0.0.0.0 \
        --authrpc.vhosts=* \
        --authrpc.jwtsecret=/var/lib/shared/jwtsecret \
        --metrics \
        --metrics.addr=0.0.0.0 \
        --metrics.port=6060 \
        --port=30303 \
        --builder \
        --builder.remote_relay_endpoint=http://helix-relay:4040 \
        --builder.beacon_endpoints=http://beacon:4000 \
        --miner.etherbase=0x614561D2d143621E126e87831AEF287678B442b8 \
        --miner.extradata="Bolt Builder"
