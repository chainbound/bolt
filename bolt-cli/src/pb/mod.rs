mod v1;

/// Re-exported protobuf API for the ETH2 remote signer service.
pub mod eth2_signer_api {

    #[allow(unused_imports)]
    pub use super::v1::{
        account_manager_client::AccountManagerClient, lister_client::ListerClient,
        sign_request::Id as SignRequestId, signer_client::SignerClient,
        wallet_manager_client::WalletManagerClient, Account, DistributedAccount,
        ListAccountsRequest, ListAccountsResponse, LockAccountRequest, LockAccountResponse,
        LockWalletRequest, LockWalletResponse, MultisignRequest, MultisignResponse, ResponseState,
        SignRequest, SignResponse, UnlockAccountRequest, UnlockAccountResponse,
        UnlockWalletRequest, UnlockWalletResponse,
    };
}
