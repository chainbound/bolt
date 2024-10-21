[flashbots mev-boost readme](README.flashbots.md)

# Bolt MEV-Boost

Bolt MEV-Boost is a fork of the Flashbots MEV-Boost package that
implements the functionality of the Constraints API.

## How it works

The MEV-Boost package has the standard functionality of the Flashbots MEV-Boost, but with the added functionality of the
Constraints API which can be summarized as follows:

1. Propagate incoming constraint messages to relays
2. Validate incoming headers and inclusion proofs
3. Forward the best bid to the proposer for signing
