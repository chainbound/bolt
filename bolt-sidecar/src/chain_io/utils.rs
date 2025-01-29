use std::{collections::HashMap, str::FromStr};

use alloy::{
    contract::Error as ContractError,
    primitives::{keccak256, Bytes, FixedBytes, B512},
    sol_types::SolInterface,
    transports::TransportError,
};
use ethereum_consensus::primitives::BlsPublicKey;

/// A 20-byte compressed hash of a BLS public key.
///
/// Reference: https://github.com/chainbound/bolt/blob/bec46baae6d7c16dddd81e5e72710ca8e3064f82/bolt-contracts/script/holesky/validators/RegisterValidators.s.sol#L65-L69
pub(crate) type CompressedHash = FixedBytes<20>;

/// Hash the public keys of the proposers and return a mapping with the results and their
/// pre-images.
///
/// This follows the same implementation done on-chain in the BoltValidators contract.
pub fn pubkey_hashes(keys: &[BlsPublicKey]) -> HashMap<CompressedHash, BlsPublicKey> {
    HashMap::from_iter(keys.iter().map(|key| (pubkey_hash(key), key.clone())))
}

/// Hash the public key of the proposer. This follows the same
/// implementation done on-chain in the BoltValidators contract.
///
/// Reference: https://github.com/chainbound/bolt/blob/bec46baae6d7c16dddd81e5e72710ca8e3064f82/bolt-contracts/script/holesky/validators/RegisterValidators.s.sol#L65-L69
pub fn pubkey_hash(key: &BlsPublicKey) -> CompressedHash {
    let digest = pubkey_hash_digest(key);
    let hash = keccak256(digest);
    CompressedHash::from_slice(hash.get(0..20).expect("hash is longer than 20 bytes"))
}

fn pubkey_hash_digest(key: &BlsPublicKey) -> B512 {
    let mut onchain_pubkey_repr = B512::ZERO;

    // copy the pubkey bytes into the rightmost 48 bytes of the 512-bit buffer.
    // the result should look like this:
    //
    // 0x00000000000000000000000000000000b427fd179b35ef085409e4a98fb3ab84ee29c689df5c64020eab0b20a4f91170f610177db172dc091682df627c9f4021
    // |<---------- 16 bytes ---------->||<----------------------------------------- 48 bytes ----------------------------------------->|
    onchain_pubkey_repr[16..].copy_from_slice(key);
    onchain_pubkey_repr
}

/// Try to decode a contract error into a specific Solidity error interface.
/// If the error cannot be decoded or it is not a contract error, return the original error.
///
/// Example usage:
///
/// ```rust ignore
/// sol! {
///    library ErrorLib {
///       error SomeError(uint256 code);
///    }
/// }
///
/// // call a contract that may return an error with the SomeError interface
/// let returndata = match myContract.call().await {
///    Ok(returndata) => returndata,
///    Err(err) => {
///         let decoded_error = try_decode_contract_error::<ErrorLib::ErrorLibError>(err)?;
///        // handle the decoded error however you want; for example, return it
///         return Err(decoded_error);
///    },
/// }
/// ```
pub fn try_parse_contract_error<T: SolInterface>(error: ContractError) -> Result<T, ContractError> {
    match error {
        ContractError::TransportError(TransportError::ErrorResp(resp)) => {
            let data = resp.data.unwrap_or_default();
            let data = data.get().trim_matches('"');
            let data = Bytes::from_str(data).unwrap_or_default();

            T::abi_decode(&data, true).map_err(Into::into)
        }
        _ => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use alloy::hex;
    use ethereum_consensus::primitives::BlsPublicKey;

    use super::pubkey_hash;

    #[test]
    fn test_public_key_hash() {
        let bytes = hex!("87cbbfe6f08a0fd424507726cfcf5b9df2b2fd6b78a65a3d7bb6db946dca3102eb8abae32847d5a9a27e414888414c26").as_ref();
        let bls_public_key = BlsPublicKey::try_from(bytes).expect("valid bls public key");
        let hash = pubkey_hash(&bls_public_key);
        assert_eq!(hex::encode(hash.as_slice()), "cf44d8bca49d695164be6796108cf788d8d056e1");
    }
}
