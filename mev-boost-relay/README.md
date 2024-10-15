[flashbots mev-boost-relay readme](README.flashbots.md)

# Bolt MEV-Boost Relay

Bolt MEV-Boost Relay is a fork of the Flashbots MEV-Boost Relay package that
implements the functionality of the Constraints API.

## How it works

The MEV-Boost Relay package has the standard functionality of the Flashbots MEV-Boost Relay,
but with the added functionality of the Constraints API which can be summarized as follows:

1. Listen for incoming constraint messages from proposers
2. Propagate constraints to connected builders
3. Validate incoming signed bids and inclusion proofs from builders
4. Forward the best bid to the proposer's MEV-Boost sidecar
