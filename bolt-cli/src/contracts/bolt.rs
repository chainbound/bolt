use alloy::sol;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface BoltValidators {
        /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
        /// @dev This function allows anyone to register a list of Validators.
        /// @param pubkeyHashes List of BLS public key hashes for the Validators to be registered
        /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
        /// @param authorizedOperator The address of the authorized operator
        function batchRegisterValidatorsUnsafe(bytes20[] calldata pubkeyHashes, uint32 maxCommittedGasLimit, address authorizedOperator);

        error KeyNotFound();
        error InvalidQuery();
        #[derive(Debug)]
        error ValidatorDoesNotExist(bytes20 pubkeyHash);
        error InvalidAuthorizedOperator();
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    struct SignatureWithSaltAndExpiry {
        bytes signature;
        bytes32 salt;
        uint256 expiry;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface BoltEigenLayerMiddleware {
        /// @notice Allow an operator to signal opt-in to Bolt Protocol.
        /// @dev This requires calling the EigenLayer AVS Directory contract to register the operator.
        /// EigenLayer internally contains a mapping from `msg.sender` (our AVS contract) to the operator.
        /// The msg.sender of this call will be the operator address.
        function registerOperator(string calldata rpc, SignatureWithSaltAndExpiry calldata operatorSignature) public;
    }
}
