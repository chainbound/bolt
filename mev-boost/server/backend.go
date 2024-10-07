package server

const (
	// Router paths
	pathStatus              = "/eth/v1/builder/status"
	pathRegisterValidator   = "/eth/v1/builder/validators"
	pathGetHeader           = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetHeaderWithProofs = "/eth/v1/builder/header_with_proofs/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetPayload          = "/eth/v1/builder/blinded_blocks"

	// Constraints namespace paths
	pathSubmitConstraint = "/constraints/v1/builder/constraints"
	pathDelegate         = "/constraints/v1/builder/delegate"
	pathRevoke           = "/constraints/v1/builder/revoke"

	// // Relay Monitor paths
	// pathAuctionTranscript = "/monitor/v1/transcript"
)
