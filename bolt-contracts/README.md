# Bolt Contracts

## Table of Contents

- [Overview](#overview)
- [Validator Registration: `BoltValidators`](#validator-registration-boltvalidators)
- [Bolt Network Entrypoint: `BoltManager`](#bolt-network-entrypoint-boltmanager)
  - [Symbiotic Integration guide for Staking Pools](#symbiotic-integration-guide-for-staking-pools)
  - [Symbiotic Integration guide for Operators](#symbiotic-integration-guide-for-operators)
  - [Eigenlayer Integration guides](#eigenlayer-integration-guides)
- [Fault Proof Challenge and Slashing: `BoltChallenger`](#fault-proof-challenge-and-slashing-boltchallenger)
- [Testing](#testing)
- [Security Considerations](#security-considerations)
- [Conclusion](#conclusion)

## Overview

The Bolt smart contracts cover the following components:

- Registration and delegation logic for validators to authenticate and opt-in to Bolt
- Flexible restaking integrations for staking pools and node operators
- (WIP) Fault proof challenge and slashing logic for validators

## Validator Registration: `BoltValidators`

The [`BoltValidators`](./src/contracts/BoltValidators.sol) contract is the only point of entry for
validators to signal their intent to participate in Bolt Protocol and authenticate with their BLS private key.

The registration process includes the following steps:

1. Validator signs a message with their BLS private key. This is required to prove that the
   validator private key is under their control and that they are indeed its owner.
2. Validator calls the `registerValidator` function providing:
   1. Their BLS public key
   2. The BLS signature of the registration message
   3. The address of the authorized collateral provider
   4. The address of the authorized operator

Until the Pectra hard-fork will be activated, the contract will also expose a `registerValidatorUnsafe` function
that will not check the BLS signature. This is gated by a feature flag that will be turned off post-Pectra and
will allow us to test the registration flow in a controlled environment.

## Bolt Network Entrypoint: `BoltManager`

The [`BoltManager`](./src/contracts/BoltManager.sol) contract is a crucial component of Bolt that
integrates with restaking ecosystems Symbiotic and Eigenlayer. It manages the registration and
coordination of validators, operators, and vaults within the Bolt network.

Key features include:

1. Registration of Symbiotic Operators and Vaults / EigenLayer Operators and Strategies
2. Whitelisting of collateral assets used to back commitments
3. Retrieval of operator stake and proposer status from their pubkey
4. Integration with Symbiotic/EigenLayer

### Symbiotic Integration guide for Staking Pools

As a staking pool, it is assumed that you are already in control of a Symbiotic Vault.
If not, please refer to the [Symbiotic docs](https://docs.symbiotic.fi/handbooks/Handbook%20for%20Vaults)
on how to spin up a Vault and start receiving stake from your node operators.

Opting into Bolt works as any other Symbiotic middleware integration. Here are the steps:

1. Make sure your vault collateral is whitelisted in `BoltManager` by calling `isSymbioticCollateralWhitelisted`.
2. Register as a vault in `BoltManager` by calling `registerSymbioticVault`.
3. Verify that your vault is active in `BoltManager` by calling `isSymbioticVaultEnabled`.
4. Set the network limit for your vault in Symbiotic with `Vault.delegator().setNetworkLimit()`.
5. You can now start approving operators that opt in to your vault directly in Symbiotic.
6. When you assign shares to operators, they are able to provide commitments on behalf of your collateral.

### Symbiotic Integration guide for Operators

As an operator, you will need to opt-in to the Bolt Network and any Vault that trusts you to provide
commitments on their behalf.

The opt-in process requires the following steps:

1. register in Symbiotic with `OperatorRegistry.registerOperator()`.
2. opt-in to the Bolt network with `OperatorNetworkOptInService.optIn(networkAddress)`.
3. opt-in to any vault with `OperatorVaultOptInService.optIn(vaultAddress)`.
4. register in Bolt with `BoltManager.registerSymbioticOperator(operatorAddress)`.
5. get approved by the vault.
6. start providing commitments with the stake provided by the vault.

### EigenLayer Integration Guide for Bolt Validators and Operators

In the Bolt ecosystem, the integration process slightly varies depending on whether you are part of a **staking pool** or you are a **solo staker**.
Below, we outline the steps for both scenarios and highlight the differences.

**For Staking Pools**

To participate in the Bolt Actively Validated Service (AVS) via EigenLayer as part of a staking pool,
follow the standard procedures outlined in the [EigenLayer documentation](https://docs.eigenlayer.xyz/).
In particular, the validators will need to point to a common Node Operator.
However, Bolt’s integration introduces some additional steps that differ from the classic AVS onboarding process:

1. **Ensure Collateral is Whitelisted**: Verify that your underlying collateral strategy is whitelisted in the `BoltManager`
   contract by calling the `isEigenLayerCollateralWhitelisted` function. Bolt requires specific collateral types to maintain compatibility and security within its system.
2. **Register the Validators**: in Bolt, you need to register your validator in the `BoltValidators`
   contract by invoking the `BoltValidators.registerValidator function`. This step is crucial for your validator to be recognized and to participate in Bolt’s protocol.
3. **Register as an Operator**: Register yourself as an operator in the `BoltManager` contract by calling the
   `BoltManager.registerEigenLayerOperator` function. This formalizes your role within the Bolt network and allows you to manage operations effectively.
4. **Register the EigenLayer Strategy**: Finally, register the EigenLayer strategy you are using for restaking if it has not been done by someones else.
   This ensures that your restaked assets are correctly integrated with Bolt’s system.

**For Solo Stakers**

In the case of solo stakers, **the staker and operator are controlled by the same entity**, known as the proposer.
This assumption is made because preconfirmation fees are paid directly to the proposer using priority fees.
Having both roles unified simplifies fee distribution and aligns incentives.

## Fault Proof Challenge and Slashing: `BoltChallenger`

WIP

## Testing

We use Forge, a fast and flexible Ethereum testing framework, for our smart contract tests.
Here's a guide to running the test suite for the Bolt contracts:

1. Make sure you have Forge installed. If not, follow the [installation guide](https://book.getfoundry.sh/getting-started/installation).

2. Navigate to the `bolt-contracts` directory

3. Run all tests

   ```
   forge test
   ```

4. Run tests with verbose output:

   ```
   forge test -vvv
   ```

## Security Considerations

While the Bolt Contracts have been designed with security best practices in mind, it's important
to note that they are still undergoing audits and should not be used in production environments without
thorough review and testing. As with any smart contract system, users should exercise caution and conduct
their own due diligence before interacting with these contracts.

The following considerations should be taken into account before interacting with smart contracts:

- Restaking is a complex process that involves trusting external systems and smart contracts.
- Validators should be aware of the potential for slashing if they fail to meet their commitments or engage in malicious behavior.
- Smart contracts are susceptible to bugs and vulnerabilities that could be exploited by attackers.

## Conclusion

The Bolt smart contracts provide a robust and flexible framework for integrating validator registration,
delegation, and restaking mechanism within the Bolt Ecosystem.

By leveraging the power and security of Symbiotic and Eigenlayer solutions, Bolt offers a sophisticated
solution for staking pools that wish to opt-in to multiple conditions with extreme granularity.
