use ethers::{
    abi::{Detokenize, Token, Uint},
    types::Address,
};

pub enum RegistrantStatus {
    Inactive,
    Active,
    Frozen,
    Exiting,
}

pub struct RegistrantMetadata {
    rpc: String,
    bytes: String,
}

pub struct Registrant {
    // The address of the operator
    operator: Address,
    // The validator indexes this registrant is responsible for
    validator_indexes: Vec<Uint>,
    entered_at: Uint,
    exit_initiated_at: Uint,
    balance: Uint,
    status: RegistrantStatus,
    metadata: RegistrantMetadata,
}
