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

### EigenLayer Integration Guide for Node Operators and Solo Stakers

Participants in the Bolt Actively Validated Service (AVS) via EigenLayer can be
be either a Node Operator (NO) in a staking pool or a solo staker.
This is because preconfirmations fees are paid directly to
Ethereum validators by using the priority fees of the transactions.
Without loss of generality, we will assume the reader of this guide is a Node Operator,
since the same steps apply to solo stakers.

> [!NOTE]
> Following EigenLayer's terminology, in the context of the Bolt AVS the "Operator" is an
> Ethereum address owned by an Ethereum validator.

Next, you need to follow the standard procedure outlined in the
[EigenLayer documentation](https://docs.eigenlayer.xyz/) to opt into EigenLayer. Let's go through the steps:

1. As an Operator, you register into EigenLayer using [`DelegationManager.registerAsOperator`](https://github.com/Layr-Labs/eigenlayer-contracts/blob/mainnet/src/contracts/core/DelegationManager.sol#L107-L119).

2. As an Ethereum validator offering precofirmations a NO needs some collateral in
   order to be economically credible. In order to do that, some entities known as a "stakers"
   need to deposit whitelisted Liquid Staking Tokens (LSTs)
   into an appropriate "Strategy" associated to the LST via the
   [`StrategyManager.depositIntoStrategy`](https://github.com/Layr-Labs/eigenlayer-contracts/blob/mainnet/src/contracts/core/StrategyManager.sol#L105-L110),
   so that the Operator has a `min_amount` (TBD) of collateral associated to it.
   Whitelisted LSTs are exposed by the `BoltEigenLayerMiddleware` contract
   in the `getWhitelistedCollaterals` function.
   Note that NOs and stakers can be two different entities
   _but there is fully trusted relationship as stakers will be slashed if a NO misbehaves_.
   As such, it is expected this will lead only NOs themselves to be the sole stakers.

3. After the stakers have deposited their collateral into a strategy they need
   to choose you as their operator. To do that, they need to call the function
   [`DelegationManager.delegateTo`](https://github.com/Layr-Labs/eigenlayer-contracts/blob/mainnet/src/contracts/core/DelegationManager.sol#L154-L163).

4. As an Operator you finally opt into the Bolt AVS by interacting with the `BoltEigenLayerMiddleware`.
   This consists in calling the function `BoltEigenLayerMiddleware.registerOperatorToAVS`.
   The payload is a signature whose digest consists of:

   1. your operator address
   2. the `BoltEigenLayerMiddleware` contract address
   3. a salt
   4. an expiry 2.

   The contract will then forward the call to the [`AVSDirectory.registerOperatorToAVS`](https://github.com/Layr-Labs/eigenlayer-contracts/blob/mainnet/src/contracts/core/AVSDirectory.sol#L64-L108)
   with the `msg.sender` set to the Bolt AVS contract. Upon successful verification of the signature,
   the operator is considered `REGISTERED` in a mapping `avsOperatorStatus[msg.sender][operator]`.

Lastly, a NO needs to interact with both the `BoltValidators` and `BoltEigenLayerMiddleware`
contract. This is needed for internal functioning of the AVS and to make RPCs aware that you are a
registered operator and so that they can forward you preconfirmation requests.

The steps required are the following:

1. Register all the validator public keys you want to use with Bolt via the `BoltValidators.registerValidator`.
   If you own more than one validator public key,
   you can use the more gas-efficient `BoltValidators.batchRegisterValidators` function.
   The `authorizedOperator` argument must be the same Ethereum address used for
   opting into EigenLayer as an Operator.

2. Register the same Operator address in the `BoltEigenLayerMiddleware` contract by calling
   the `BoltEigenLayerMiddleware.registerOperator` function. This formalizes your role within the Bolt network
   and allows you to manage operations effectively, such as pausing or resuming
   your service.

3. Register the EigenLayer strategy you are using for restaking _if it has not been done by someone else already_.
   This ensures that your restaked assets are correctly integrated with Bolt’s system.

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
