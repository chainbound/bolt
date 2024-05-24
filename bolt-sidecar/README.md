# `bolt-sidecar`
The Bolt sidecar is the main entrypoint for proposers to issue proposer commitments. Proposers should point their `builder-api` to the Bolt sidecar API in order to enable it.

## Functionality
The sidecar is responsible for:
1. Registering the preferences of the proposer
2. Accepting (or rejecting) commitment requests
3. Implementing pricing strategies
4. Building a block template & simulation
5. Communicating constraints to the downstream PBS pipeline
6. Verifying any incoming builder bids from mev-boost
7. Dealing with PBS failures by falling back to the local template

### Local Block Template
The local block template serves 3 purposes:
1. Building a fallback block in case the PBS pipeline fails
2. Maintaining intermediate state to simulate commitment requests on
3. Syncing with Ethereum state and invalidating stale commitments

*What do we simulate?*
We only simulate in order to verify the validity of the transaction according to protocol rules. This means:
1. The transaction sender should be able to pay for it: `balance >= value + fee`
2. The transaction nonce should be higher than any previously known nonce
3. The base fee should be able to cover the maximum base fee the target block can have: `max_base_fee = current_base_fee * 1.125^block_diff`

*Building strategy*
The block template is built and simulated on in FIFO order.

*Updating state*
We store a list of commitment addresses along with their account state. For each new block, we should update that state and check if we have to invalidate any commitments. This is critical as we don't want to return an invalid block
in case a fallback block is required.
