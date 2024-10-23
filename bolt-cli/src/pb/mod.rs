mod v1;

/// Re-exported protobuf API for the ETH2 remote signer service.
pub mod eth2_signer_api {

    #[allow(unused_imports)]
    pub use super::v1::{
        lister_client::ListerClient, sign_request::Id as SignRequestId,
        signer_client::SignerClient, Account, DistributedAccount, ListAccountsRequest,
        ListAccountsResponse, ResponseState, SignRequest, SignResponse,
    };
}
