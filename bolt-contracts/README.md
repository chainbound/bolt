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

## Symbiotic Operator and Vault Registration: `BoltManager`

TODO
