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

1. Retrieval of operator stake and proposer status from their pubkey
2. Integration with Symbiotic
3. Integration with Eigenlayer

Specific functionalities about the restaking protocols are handled inside
the `IBoltMiddleware` contracts, such as `BoltSymbioticMiddleware` and `BoltEigenlayerMiddleware`.

### Symbiotic Integration guide for Staking Pools

As a staking pool, it is assumed that you are already in control of a Symbiotic Vault.
If not, please refer to the [Symbiotic docs](https://docs.symbiotic.fi/handbooks/Handbook%20for%20Vaults)
on how to spin up a Vault and start receiving stake from your node operators.

Opting into Bolt works as any other Symbiotic middleware integration. Here are the steps:

1. Make sure your vault collateral is whitelisted in `BoltSymbioticMiddleware` by calling `isCollateralWhitelisted`.
2. Register as a vault in `BoltSymbioticMiddleware` by calling `registerVault`.
3. Verify that your vault is active in `BoltSymbioticMiddleware` by calling `isVaultEnabled`.
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
4. register in Bolt with `BoltSymbioticMiddleware.registerOperator(operatorAddress)`.
5. get approved by the vault.
6. start providing commitments with the stake provided by the vault.

### EigenLayer Integration Guide for Node Operators and Solo Stakers

> [!NOTE]
> Without loss of generality, we will assume the reader of this guide is a Node
> Operator (NO), since the same steps apply to solo stakers.

As a Node Operator you will be an ["Operator"](https://docs.eigenlayer.xyz/eigenlayer/overview/key-terms)
in the Bolt AVS built on top of EigenLayer. This requires
running an Ethereum validator and the Bolt sidecar in order issue
preconfirmations.

The Operator will be represented by an Ethereum address that needs
to follow the standard procedure outlined in the
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

The [`BoltChallenger`](./src/contracts/BoltChallenger.sol) contract is the component responsible
for handling fault attribution in the case of a validator failing to meet their commitments.

In short, the challenger contract allows any user to challenge a validator's commitment by opening
a dispute with the following inputs:

1. The signed commitment made by the validator (or a list of commitments on the same slot)
2. An ETH bond to cover the cost of the dispute and disincentivize frivolous challenges

The entrypoint is the `openChallenge` function. Once a challenge is opened, a `ChallengeOpened` event
is emitted, and any arbitrator has a time window to submit a valid response to settle the dispute.

### Dispute resolution

The dispute resolution process is one-shot and requires the arbitrator to submit all necessary evidence
of the validator's correct behaviour within the challenge time window.

The arbitrator is _anyone_ who can submit a valid response to the challenge. It doesn't have to be the
validator themselves. There is however one limitation: the time window for submitting a response must be
respected in the following way:

- Start: the target block must be justified by LMD-GHOST: a minimum of 32 slots must have passed
- End: depending on the EVM block hash oracle:
  - . If using the `BLOCKHASH` EVM opcode, the window is limited to 256 blocks (roughly 1 hour)
  - . If using the [EIP-2935](https://eips.ethereum.org/EIPS/eip-2935) historical oracle, the window is limited to 8192 blocks (roughly 1 day)

The inputs to the resolution process are as follows:

1. The ID of the challenge to respond to: this is emitted in the `ChallengeOpened` event and is unique.
2. The [inclusion proofs](https://github.com/chainbound/bolt/blob/6c0f1b696cfe3de7e7e3830ac28c369c6ddf271e/bolt-contracts/src/interfaces/IBoltChallenger.sol#L39), consisting of the following components:
   a. the block number of the block containing the committed transactions (we call it "inclusionBlock")
   b. the RLP-encoded block header of the block **before** the one containing the committed transactions (we call it "previousBlock")
   b. the RLP-encoded block header of the block containing the included transactions (aka "inclusionBlock")
   c. the account merkle proofs of the sender of the committed transactions against the previousBlock's state root
   d. the transaction merkle proofs of the included transactions against the inclusionBlock's transaction root
   e. the transaction index in the block of each included transaction

If the arbitrator submits a valid response that satisfies the requirements for the challenge, the
challenge is considered `DEFENDED` and the challenger's bond is slashed to cover the cost of the dispute
and to incentivize speedy resolution.

If no arbitrators respond successfully within the challenge time window, the challenge is considered
`BREACHED` and anyone can call the `resolveExpiredChallenge()` method. The `BoltChallenger` will keep
track of this information for future reference.

### Slashing of validators

If a challenge is `BREACHED` (as per the above definition), the validator's stake should be slashed to cover
the cost of a missed commitment. This is done by calling the `slash` function on the correct staking adapter
and reading into the `BoltChallenger` contract to trustlessly determine if the challenge was lost.

In practice, slashing behaviour is abstracted behind any staking adapter – an example is Symbiotic's `VetoSlasher`
which will receive a request to slash a validator's stake and will have a last opportunity to veto
the slashing request before it is executed on-chain.

Subscribing to breached challenge events from the `BoltChallenger` is a trustless way to determine if a slashing
request is valid according to Bolt Protocol rules.

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
