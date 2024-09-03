# Bolt Contracts

## Overview

The Bolt smart contracts cover the following components:

- Registration and delegation logic for validators to opt-in to the network
- Flexible restaking integrations

## Validator Registration: `BoltValidators`

The `BoltValidators` contract is the only point of entry for validators to signal their intent
to participate in Bolt Protocol and to start issuing credible commitments.

The registration process includes the following steps:

1. Validator signs a message with their BLS private key. This is required to prove that the
   validator private key is under their control and that they are indeed its owner.
2. Validator calls the `registerValidator` function providing:
   1. Their BLS public key
   2. The BLS signature of the registration message
   3. The address of the authorized collateral provider
   4. The address of the authorized operator

Until the Pectra hard-fork will be activated, the contract will also expose a `registerValidatorUnsafe` function
that will not check the BLS signature. This is gated by a feature flag that will be turned off post-Pectra.

## Symbiotic Operator and Vault Registration: `BoltManager`

TODO
