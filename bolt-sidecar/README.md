# bolt sidecar

Core functionality:

1. json-rpc server to receive prreconfirmation requests from users `eth_requestPreconfirmation`
2. save preconfirmation requests in a local cache
3. reply with a commitment ACK to the user
4. json-rpc server endpoint for builders to query the preconfirmation cache `eth_getPreconfirmations`
