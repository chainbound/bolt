#!/bin/sh

geth init --datadir=/var/lib/chaindata/geth --state.scheme=hash /var/lib/network-configs/genesis.json

geth --datadir=/var/lib/chaindata/geth --state.scheme=hash \
        --syncmode=full \
        --gcmode=archive \
        --state.scheme=hash \
        --networkid=7014190335 \
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
        --bootnodes=enode://c15b5973b8fc6e5152d1d442512e5024b25883f2e002564cfa29cc3b748d687756c9f674f021f142eeea5711697a3d43d2bc36f13b1e20fe11b341676921430e@18.192.40.76:30303?discport=30303,enode://35cd13c4d555d70b39aafa806f817c4707397f7f9b7a1d43237f73d279c318fda0e4ba8a4b10d1f8b7771992804209aa028f74bd846afc86d016c4728a1c5268@35.156.177.215:30303?discport=30303,enode://dba7a24e543cc924178ed7e0066e5e40caa17607474a25b50e4bea7b565dee9719970a33e3e5beb4ad84832dad91bd9fe8de1f6cb1c6a7cb6e90c3bc10a20c67@18.199.185.236:30303?discport=30303,enode://a3317a4ec26ad3cedddb1951105699757fc74ed35c7bc6e31a6fe08b383fad3540ccf7c2f6d617411c74a22cf81a8a3898cf845c7a1501a969229c6ee046042f@52.28.153.174:30303?discport=30303 \
        --builder \
        --builder.remote_relay_endpoint=http://relay-api:9062 \
        --builder.beacon_endpoints=http://beacon:4000 \
        --builder.genesis_validators_root=0xa55f9089402f027c67db4a43b6eb7fbb7b2eb79f194a90a2cd4f31913e47b336 \
        --builder.genesis_fork_version=0x10000000 \
        --miner.etherbase=0x614561D2d143621E126e87831AEF287678B442b8 \
        --miner.extradata="Bolt Builder"