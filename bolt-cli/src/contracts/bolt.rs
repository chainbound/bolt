use alloy::sol;
use serde::Serialize;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface BoltValidators {
        #[derive(Debug, Serialize)]
        struct ValidatorInfo {
            bytes20 pubkeyHash;
            uint32 maxCommittedGasLimit;
            address authorizedOperator;
            address controller;
        }

        /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
        /// @dev This function allows anyone to register a list of Validators.
        /// @param pubkeyHashes List of BLS public key hashes for the Validators to be registered
        /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
        /// @param authorizedOperator The address of the authorized operator
        function batchRegisterValidatorsUnsafe(bytes20[] calldata pubkeyHashes, uint32 maxCommittedGasLimit, address authorizedOperator);

        /// @notice Get a validator by its BLS public key hash
        /// @param pubkeyHash BLS public key hash of the validator
        /// @return ValidatorInfo struct
        function getValidatorByPubkeyHash(bytes20 pubkeyHash) public view returns (ValidatorInfo memory);

        #[derive(Debug)]
        error KeyNotFound();
        #[derive(Debug)]
        error InvalidQuery();
        #[derive(Debug)]
        error ValidatorDoesNotExist(bytes20 pubkeyHash);
        #[derive(Debug)]
        error ValidatorAlreadyExists(bytes20 pubkeyHash);
        #[derive(Debug)]
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

        /// @notice Deregister an EigenLayer operator from working in Bolt Protocol.
        /// @dev This requires calling the EigenLayer AVS Directory contract to deregister the operator.
        /// EigenLayer internally contains a mapping from `msg.sender` (our AVS contract) to the operator.
        function deregisterOperator() public;

        error AlreadyRegistered();
        error NotOperator();
        error NotRegistered();
        error KeyNotFound(address key);
        error SaltSpent();

        // From IDelegationManager
        /// @dev Thrown when an account is not actively delegated.
        error NotActivelyDelegated();
        /// @dev Thrown when `operator` is not a registered operator.
        error OperatorNotRegistered();
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    interface BoltSymbioticMiddleware {
        /// @notice Allow an operator to signal opt-in to Bolt Protocol.
        /// msg.sender must be an operator in the Symbiotic network.
        function registerOperator(string calldata rpc) public;

        /// @notice Deregister a Symbiotic operator from working in Bolt Protocol.
        /// @dev This does NOT deregister the operator from the Symbiotic network.
        function deregisterOperator() public;

        /// @notice Get the collaterals and amounts staked by an operator across the supported strategies.
        ///
        /// @param operator The operator address to get the collaterals and amounts staked for.
        /// @return collaterals The collaterals staked by the operator.
        /// @dev Assumes that the operator is registered and enabled.
        function getOperatorCollaterals(address operator) public view returns (address[] memory, uint256[] memory);

        error AlreadyRegistered();
        error NotOperator();
        error NotRegistered();
        error KeyNotFound();
    }
}
