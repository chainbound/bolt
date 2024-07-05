#!/bin/sh

lighthouse beacon_node \
        --debug-level=info \
        --datadir=/var/lib/chaindata \
        --disable-enr-auto-update \
        --enr-address=136.243.76.36 \
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
        --checkpoint-sync-url=https://bn.bootnode.helder-devnets.xyz/ \
        --execution-endpoints=http://builder:8551 \
        --subscribe-all-subnets \
        --metrics \
        --metrics-address=0.0.0.0 \
        --metrics-allow-origin=* \
        --metrics-port=5054 \
        --enable-private-discovery \
        --testnet-dir=/var/lib/network-configs \
        --jwt-secrets=/var/lib/shared/jwtsecret \
        --boot-nodes=enr:-Iq4QK3EWjpB_Wh4Nh9qDWsIlkwCo-ltVJIOZintRmXlq4BqSO3MgChdjo5bNSc_dBVcnhM_CZidGE-CMjazCeJhn7OGAZA6aA31gmlkgnY0gmlwhDQ6SFGJc2VjcDI1NmsxoQN4MIj6Xe7PBxpfvrpyDe2OkrcIq0gdj38hHXpWjB6Zl4N1ZHCCIyk,enr:-LK4QJIhICEs-MIlzVGEOJRco5B3eR1HjsoPrnlNdCifHlT_NQCaY51Z-ntBIgUQmNRcEBqBogOhh43BYdMR_d9Z-DgKh2F0dG5ldHOIAAYAAAAAAACEZXRoMpBLd1oGYBMnNj9CDwAAAAAAgmlkgnY0gmlwhDQ6SFGJc2VjcDI1NmsxoQOy0WhSLuSWpKXex_SG9dn4bOk-LURo7ZjaUuQ1Fbdbk4N0Y3CCIyiDdWRwgiMo,enr:-MS4QKp7W7f8BsoB04SovlJFZDhs67ZgFK_h5TwBXItLoJfGMPDCLnReASmmig_7kxCNf08e68FrCVM3FcPV0ttR92sWh2F0dG5ldHOIAAAwAAAAAACEZXRoMpBLd1oGYBMnNj9CDwAAAAAAgmlkgnY0gmlwhBLAKEyEcXVpY4IjKYlzZWNwMjU2azGhAxUCn447F0j2DEeA-PqFdp5GP3VpXRWgia2yKjeT62G2iHN5bmNuZXRzAIN0Y3CCIyiDdWRwgiMo,enr:-MS4QAvcfEmj00GqJcvkjcvQIhBi6pJQ9Znnp2Hr_Hh4YEOzWMENkleVt-vGAAgz8bhFedR5JkcfuzHTzY-9EpB43n4Ph2F0dG5ldHOIAAAAAAAAAMCEZXRoMpBLd1oGYBMnNj9CDwAAAAAAgmlkgnY0gmlwhCOcsdeEcXVpY4IjKYlzZWNwMjU2azGhAo8AZqqrsuBrbMLHdavhLdAxLWpcSk-SPDuqjJt5Fe_oiHN5bmNuZXRzD4N0Y3CCIyiDdWRwgiMo,enr:-MS4QDvmIhX8vI8_kK62XXbO9gnrm-YuzXKo-OS07uRKLgijLfxeUPvtKU-Ps2RnxOEoNq9RPqhbeVdAVYO71eAJvRkPh2F0dG5ldHOIAAAAAAAAABiEZXRoMpBLd1oGYBMnNj9CDwAAAAAAgmlkgnY0gmlwhBLHueyEcXVpY4IjKYlzZWNwMjU2azGhA4ZmLIctckMGhbOwtpgUI2RNeH2S7LXmwpX_onBAfW_AiHN5bmNuZXRzD4N0Y3CCIyiDdWRwgiMo,enr:-MS4QGcM6eqjhCp_Ag7gMzkU8ks7F-S2QsoIdeEsbcB8TPefYK19ymkwmTcpmZfbTJRMwwAvqdOMmGWEAI5GYv_7xZwTh2F0dG5ldHOIAAAAAAAMAACEZXRoMpBLd1oGYBMnNj9CDwAAAAAAgmlkgnY0gmlwhDQcma6EcXVpY4IjKYlzZWNwMjU2azGhAnXOGXUDHbcgGJeZ9-ftr8cihtkyfUfNlpQNe9G8P2PCiHN5bmNuZXRzD4N0Y3CCIyiDdWRwgiMo