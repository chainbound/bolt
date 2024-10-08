package server

const (
	// Router paths
	pathStatus              = "/eth/v1/builder/status"
	pathRegisterValidator   = "/eth/v1/builder/validators"
	pathGetHeader           = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetHeaderWithProofs = "/eth/v1/builder/header_with_proofs/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetPayload          = "/eth/v1/builder/blinded_blocks"

	// Constraints namespace paths
	// Ref: https://docs.boltprotocol.xyz/api/builder#constraints
	pathSubmitConstraint = "/constraints/v1/builder/constraints"
	// Ref: https://docs.boltprotocol.xyz/api/builder#delegate
	pathDelegate = "/constraints/v1/builder/delegate"
	// Ref: https://docs.boltprotocol.xyz/api/builder#revoke
	pathRevoke = "/constraints/v1/builder/revoke"

	// // Relay Monitor paths
	// pathAuctionTranscript = "/monitor/v1/transcript"
)
