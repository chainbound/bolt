package server

const (
	// Router paths
	pathStatus              = "/eth/v1/builder/status"
	pathRegisterValidator   = "/eth/v1/builder/validators"
	pathSubmitConstraint    = "/eth/v1/builder/constraints"
	pathGetHeader           = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetHeaderWithProofs = "/eth/v1/builder/header_with_proofs/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetPayload          = "/eth/v1/builder/blinded_blocks"

	// // Relay Monitor paths
	// pathAuctionTranscript = "/monitor/v1/transcript"
)
