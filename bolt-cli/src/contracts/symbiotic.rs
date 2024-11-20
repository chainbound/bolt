use alloy::sol;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    // Reference source code: https://github.com/symbioticfi/core/blob/main/src/interfaces/service/IOptInService.sol
    interface IOptInService {
        /**
         * @notice Get if a given "who" is opted-in to a particular "where" entity at a given timestamp using a hint.
         * @param who address of the "who"
         * @param where address of the "where" entity
         * @param timestamp time point to get if the "who" is opted-in at
         * @param hint hint for the checkpoint index
         * @return if the "who" is opted-in at the given timestamp
         */
        function isOptedInAt(
            address who,
            address where,
            uint48 timestamp,
            bytes calldata hint
        ) external view returns (bool);

        /**
         * @notice Check if a given "who" is opted-in to a particular "where" entity.
         * @param who address of the "who"
         * @param where address of the "where" entity
         * @return if the "who" is opted-in
         */
        function isOptedIn(address who, address where) external view returns (bool);
    }
}
