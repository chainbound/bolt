#!/bin/sh

lighthouse beacon_node \
        --network=holesky \
        --debug-level=info \
        --datadir=/var/lib/chaindata \
        --disable-enr-auto-update \
        --enr-udp-port=50050 \
        --enr-tcp-port=50050 \
        --listen-address=0.0.0.0 \
        --port=50050 \
        --http \
        --http-address=0.0.0.0 \
        --http-port=4000 \
        --http-allow-sync-stalled \
        --always-prepare-payload \
        --prepare-payload-lookahead=12000 \
        --slots-per-restore-point=32 \
        --disable-packet-filter \
        --checkpoint-sync-url=https://holesky.beaconstate.info \
        --execution-endpoints=http://builder:8551 \
        --subscribe-all-subnets \
        --metrics \
        --metrics-address=0.0.0.0 \
        --metrics-allow-origin=* \
        --metrics-port=5054 \
        --enable-private-discovery \
        --jwt-secrets=/var/lib/shared/jwtsecret
