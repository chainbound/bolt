# bolt sidecar

Core functionality:

1. JSON-RPC server to receive preconfirmation requests from users
2. Save preconfirmation requests in a local cache
3. Reply with a signed commitment ACK to the user
4. JSON-RPC server endpoint for builders to query the preconfirmation cache
