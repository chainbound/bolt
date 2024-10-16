# `bolt-sidecar`

The Bolt sidecar is the main entrypoint for proposers to issue proposer commitments. Proposers should point their `builder-api` to the Bolt sidecar API in order to enable it.

## Functionality

The sidecar is responsible for:

1. Registering the preferences of the proposer
2. Accepting (or rejecting) commitment requests
3. Implementing pricing strategies
4. Building a block template & simulation
5. Communicating constraints to the downstream PBS pipeline
6. Verifying any incoming builder bids from constraints client
7. Dealing with PBS failures by falling back to the local template

### Local Block Template

The local block template serves 3 purposes:

1. Building a fallback block in case the PBS pipeline fails
2. Maintaining intermediate state to simulate commitment requests on
3. Syncing with Ethereum state and invalidating stale commitments

_What do we simulate?_
We only simulate in order to verify the validity of the transaction according to protocol rules. This means:

1. The transaction sender should be able to pay for it: `balance >= value + fee`
2. The transaction nonce should be higher than any previously known nonce
3. The base fee should be able to cover the maximum base fee the target block can have: `max_base_fee = current_base_fee * 1.125^block_diff`

_Building strategy_
The block template is built and simulated on in FIFO order.

_Updating state_
We store a list of commitment addresses along with their account state. For each new block, we should update that state and check if we have to invalidate any commitments. This is critical as we don't want to return an invalid block
in case a fallback block is required.

## Running

- We require Anvil to be installed in the $PATH for running tests

```text
Command-line options for the Bolt sidecar

Usage: bolt-sidecar [OPTIONS]
    <--private-key <PRIVATE_KEY>|--commit-boost-address <COMMIT_BOOST_ADDRESS>|--keystore-password <KEYSTORE_PASSWORD>>

Options:
      --port <PORT>
          Port to listen on for incoming JSON-RPC requests

          [env: BOLT_SIDECAR_PORT=]
          [default: 8000]

      --beacon-api-url <BEACON_API_URL>
          URL for the beacon client

          [env: BOLT_SIDECAR_BEACON_API_URL=]
          [default: http://localhost:5052]

      --constraints-url <CONSTRAINTS_URL>
          URL for the Constraint sidecar client to use

          [env: BOLT_SIDECAR_CONSTRAINTS_URL=]
          [default: http://localhost:3030]

      --execution-api-url <EXECUTION_API_URL>
          Execution client API URL

          [env: BOLT_SIDECAR_EXECUTION_API_URL=]
          [default: http://localhost:8545]

      --engine-api-url <ENGINE_API_URL>
          Execution client Engine API URL

          [env: BOLT_SIDECAR_ENGINE_API_URL=]
          [default: http://localhost:8551]

      --constraints-proxy-port <CONSTRAINTS_PROXY_PORT>
          Constraint proxy server port to use

          [env: BOLT_SIDECAR_CONSTRAINTS_PROXY_PORT=]
          [default: 18551]

      --validator-indexes <VALIDATOR_INDEXES>
          Validator indexes of connected validators that the sidecar should accept commitments on behalf of.
          Accepted values:
            - a comma-separated list of indexes (e.g. "1,2,3,4")
            - a contiguous range of indexes (e.g. "1..4")
            - a mix of the above (e.g. "1,2..4,6..8")

          [env: BOLT_SIDECAR_VALIDATOR_INDEXES=]
          [default: ]

      --jwt-hex <JWT_HEX>
          The JWT secret token to authenticate calls to the engine API.

          It can either be a hex-encoded string or a file path to a file containing the hex-encoded secret.

          [env: BOLT_SIDECAR_JWT_HEX=]
          [default: 0xcc68d8051627b89005165f38a351242848e4c53be38d398069967ba62970edf0]

      --fee-recipient <FEE_RECIPIENT>
          The fee recipient address for fallback blocks

          [env: BOLT_SIDECAR_FEE_RECIPIENT=]
          [default: 0x0000000000000000000000000000000000000000]

      --builder-private-key <BUILDER_PRIVATE_KEY>
          Secret BLS key to sign fallback payloads with (If not provided, a random key will be used)

          [env: BOLT_SIDECAR_BUILDER_PRIVATE_KEY=]
          [default: 0x240872ca0812e33503482a886e05dfe30ae9cf757bf5c040e70eac685e419c6e]

      --max-commitments-per-slot <MAX_COMMITMENTS_PER_SLOT>
          Max number of commitments to accept per block

          [env: BOLT_SIDECAR_MAX_COMMITMENTS=]
          [default: 128]

      --max-committed-gas-per-slot <MAX_COMMITTED_GAS_PER_SLOT>
          Max committed gas per slot

          [env: BOLT_SIDECAR_MAX_COMMITTED_GAS=]
          [default: 10000000]

      --min-priority-fee <MIN_PRIORITY_FEE>
          Min priority fee to accept for a commitment

          [env: BOLT_SIDECAR_MIN_PRIORITY_FEE=]
          [default: 1000000000]

      --chain <CHAIN>
          Chain on which the sidecar is running

          [env: BOLT_SIDECAR_CHAIN=]
          [default: mainnet]
          [possible values: mainnet, holesky, helder, kurtosis]

      --commitment-deadline <COMMITMENT_DEADLINE>
          The deadline in the slot at which the sidecar will stop accepting new commitments for
          the next block (parsed as milliseconds)

          [env: BOLT_SIDECAR_COMMITMENT_DEADLINE=]
          [default: 8000]

      --slot-time <SLOT_TIME>
          The slot time duration in seconds. If provided, it overrides the default for the selected [Chain]

          [env: BOLT_SIDECAR_SLOT_TIME=]
          [default: 12]

      --private-key <PRIVATE_KEY>
          Private key to use for signing preconfirmation requests

          [env: BOLT_SIDECAR_PRIVATE_KEY=]

      --commit-boost-address <COMMIT_BOOST_ADDRESS>
          Socket address for the commit-boost sidecar

          [env: BOLT_SIDECAR_CB_SIGNER_URL=]

      --commit-boost-jwt-hex <COMMIT_BOOST_JWT_HEX>
          JWT in hexadecimal format for authenticating with the commit-boost service

          [env: BOLT_SIDECAR_CB_JWT_HEX=]

      --keystore-password <KEYSTORE_PASSWORD>
          The password for the ERC-2335 keystore. Reference: https://eips.ethereum.org/EIPS/eip-2335

          [env: BOLT_SIDECAR_KEYSTORE_PASSWORD=]

      --keystore-path <KEYSTORE_PATH>
          Path to the keystores folder. If not provided, the default path is used

          [env: BOLT_SIDECAR_KEYSTORE_PATH=]

  -m, --metrics-port <METRICS_PORT>
          The port on which to expose Prometheus metrics

          [env: METRICS_PORT=]
          [default: 3300]

  -d, --disable-metrics
          [env: DISABLE_METRICS=]

  -h, --help
          Print help (see a summary with '-h')
```
