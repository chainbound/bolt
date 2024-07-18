## A pre-confirmation spammer for the Helder testnet

To run the spammer, make sure to set the following environment variables in a `.env` file:

```text
PRIVATE_KEY=<your account private key with ETH on Helder>
BEACON_CLIENT_URL=<your beacon client HTTP endpoint>
```

This template can be found in the `env.example` file.

Then, just run the spammer with `cargo run`.

It will fetch all the validators of the current epoch,
and try to send a pre-confirmation to the first one registered on the Bolt registry.
If no validators are found, the program will gracefully exit. Please try again in the next epoch!
