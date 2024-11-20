use alloy::sol;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]

    // Reference source code: https://github.com/Layr-Labs/eigenlayer-contracts/blob/testnet-holesky/src/contracts/interfaces/IStrategy.sol
    //
    // NOTE: IERC20 tokens are replaced with `address` because there's no support for it: https://docs.rs/alloy-sol-macro/latest/alloy_sol_macro/macro.sol.html#solidity

    /**
    * @title Minimal interface for an `Strategy` contract.
    * @author Layr Labs, Inc.
    * @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
    * @notice Custom `Strategy` implementations may expand extensively on this interface.
    */
    interface IStrategy {
        /**
        * @notice Used to deposit tokens into this Strategy
        * @param token is the ERC20 token being deposited
        * @param amount is the amount of token being deposited
        * @dev This function is only callable by the strategyManager contract. It is invoked inside of the strategyManager's
        * `depositIntoStrategy` function, and individual share balances are recorded in the strategyManager as well.
        * @return newShares is the number of new shares issued at the current exchange ratio.
        */
        function deposit(address token, uint256 amount) external returns (uint256 shares);

        /**
        * @notice Used to withdraw tokens from this Strategy, to the `recipient`'s address
        * @param recipient is the address to receive the withdrawn funds
        * @param token is the ERC20 token being transferred out
        * @param amountShares is the amount of shares being withdrawn
        * @dev This function is only callable by the strategyManager contract. It is invoked inside of the strategyManager's
        * other functions, and individual share balances are recorded in the strategyManager as well.
        */
        function withdraw(address recipient, address token, uint256 amountShares) external;

        /**
        * @notice Used to convert a number of shares to the equivalent amount of underlying tokens for this strategy.
        * @notice In contrast to `sharesToUnderlyingView`, this function **may** make state modifications
        * @param amountShares is the amount of shares to calculate its conversion into the underlying token
        * @return The amount of underlying tokens corresponding to the input `amountShares`
        * @dev Implementation for these functions in particular may vary significantly for different strategies
        */
        function sharesToUnderlying(uint256 amountShares) external returns (uint256);

        /**
        * @notice Used to convert an amount of underlying tokens to the equivalent amount of shares in this strategy.
        * @notice In contrast to `underlyingToSharesView`, this function **may** make state modifications
        * @param amountUnderlying is the amount of `underlyingToken` to calculate its conversion into strategy shares
        * @return The amount of underlying tokens corresponding to the input `amountShares`
        * @dev Implementation for these functions in particular may vary significantly for different strategies
        */
        function underlyingToShares(uint256 amountUnderlying) external returns (uint256);

        /**
        * @notice convenience function for fetching the current underlying value of all of the `user`'s shares in
        * this strategy. In contrast to `userUnderlyingView`, this function **may** make state modifications
        */
        function userUnderlying(address user) external returns (uint256);

        /**
        * @notice convenience function for fetching the current total shares of `user` in this strategy, by
        * querying the `strategyManager` contract
        */
        function shares(address user) external view returns (uint256);

        /**
        * @notice Used to convert a number of shares to the equivalent amount of underlying tokens for this strategy.
        * @notice In contrast to `sharesToUnderlying`, this function guarantees no state modifications
        * @param amountShares is the amount of shares to calculate its conversion into the underlying token
        * @return The amount of shares corresponding to the input `amountUnderlying`
        * @dev Implementation for these functions in particular may vary significantly for different strategies
        */
        function sharesToUnderlyingView(uint256 amountShares) external view returns (uint256);

        /**
        * @notice Used to convert an amount of underlying tokens to the equivalent amount of shares in this strategy.
        * @notice In contrast to `underlyingToShares`, this function guarantees no state modifications
        * @param amountUnderlying is the amount of `underlyingToken` to calculate its conversion into strategy shares
        * @return The amount of shares corresponding to the input `amountUnderlying`
        * @dev Implementation for these functions in particular may vary significantly for different strategies
        */
        function underlyingToSharesView(uint256 amountUnderlying) external view returns (uint256);

        /**
        * @notice convenience function for fetching the current underlying value of all of the `user`'s shares in
        * this strategy. In contrast to `userUnderlying`, this function guarantees no state modifications
        */
        function userUnderlyingView(address user) external view returns (uint256);

        /// @notice The underlying token for shares in this Strategy
        function underlyingToken() external view returns (address token);

        /// @notice The total number of extant shares in this Strategy
        function totalShares() external view returns (uint256);

        /// @notice Returns either a brief string explaining the strategy's goal & purpose, or a link to metadata that explains in more detail.
        function explanation() external view returns (string memory);
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]

    /**
    * @title Interface for the primary entrypoint for funds into EigenLayer.
    * @author Layr Labs, Inc.
    * @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
    * @notice See the `StrategyManager` contract itself for implementation details.
    */
    interface IStrategyManager {
        /**
        * @notice Emitted when a new deposit occurs on behalf of `staker`.
        * @param staker Is the staker who is depositing funds into EigenLayer.
        * @param strategy Is the strategy that `staker` has deposited into.
        * @param token Is the token that `staker` deposited.
        * @param shares Is the number of new shares `staker` has been granted in `strategy`.
        */
        event Deposit(address staker, address token, address strategy, uint256 shares);

        /**
        * @notice Deposits `amount` of `token` into the specified `strategy`, with the resultant shares credited to `msg.sender`
        * @param strategy is the specified strategy where deposit is to be made,
        * @param token is the denomination in which the deposit is to be made,
        * @param amount is the amount of token to be deposited in the strategy by the staker
        * @return shares The amount of new shares in the `strategy` created as part of the action.
        * @dev The `msg.sender` must have previously approved this contract to transfer at least `amount` of `token` on their behalf.
        * @dev Cannot be called by an address that is 'frozen' (this function will revert if the `msg.sender` is frozen).
        *
        * WARNING: Depositing tokens that allow reentrancy (eg. ERC-777) into a strategy is not recommended.  This can lead to attack vectors
        *          where the token balance and corresponding strategy shares are not in sync upon reentrancy.
        */
        function depositIntoStrategy(address strategy, address token, uint256 amount) external returns (uint256 shares);
    }
}
