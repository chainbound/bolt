[flashbots builder readme](README.flashbots.md)

# Bolt builder

Bolt builder is a fork of the Flsahbots Builder that implements the functionality of the Constraints API.

## How it works

The builder has the standard functionality of the Flashbots builder, but with the
added functionality of the Constraints API which can be summarized as follows:

1. The builder subscribes to the relays for streams of constraints sent by proposers.
2. After receiving constraints and validating their authenticity, the builder builds a block that
   respects all constraints and includes the necessary proofs of inclusion in its bid.
3. The builder sends the signed bid as usual to the relay.
