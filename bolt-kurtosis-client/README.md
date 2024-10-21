## A preconfirmation sender for the Kurtosis devnet

To run the tool, make sure to set the following environment variables in a `.env` file:

```text
EL_PROVIDER_URL=https://rpc.helder-devnets.xyz
BEACON_CLIENT_URL=
REGISTRY_ADDRESS=0xdF11D829eeC4C192774F3Ec171D822f6Cb4C14d9
PRIVATE_KEY=
REGISTRY_ABI_PATH=./registry_abi.json
```

This template can be found in the `env.example` file.

Then, just run the tool with `cargo run`.

It will fetch all the validators of the current epoch, and try to send a
preconfirmation to the first one registered on the Bolt registry.

If no validators are found, the program will gracefully exit.
Please try again in the next epoch!
