use std::str::FromStr;

use alloy::primitives::{Address, Signature};
use axum::http::HeaderMap;

use crate::primitives::commitment::SignatureError;

use super::spec::{Error, SIGNATURE_HEADER};

/// Extracts the signature ([SIGNATURE_HEADER]) from the HTTP headers.
#[inline]
pub fn auth_from_headers(headers: &HeaderMap) -> Result<(Address, Signature), Error> {
    let auth = headers.get(SIGNATURE_HEADER).ok_or(Error::NoSignature)?;

    // Remove the "0x" prefix
    let auth = auth.to_str().map_err(|_| Error::MalformedHeader)?;

    let mut split = auth.split(':');

    let address = split.next().ok_or(Error::MalformedHeader)?;
    let address = Address::from_str(address).map_err(|_| Error::MalformedHeader)?;

    let sig = split.next().ok_or(Error::MalformedHeader)?;
    let sig = Signature::from_str(sig).map_err(|_| Error::InvalidSignature(SignatureError))?;

    Ok((address, sig))
}

#[cfg(test)]
mod test {
    use alloy::{
        primitives::TxHash,
        signers::{local::PrivateKeySigner, Signer},
    };

    use crate::primitives::commitment::ECDSASignatureExt;

    use super::*;

    #[tokio::test]
    async fn test_signature_from_headers() {
        let mut headers = HeaderMap::new();
        let hash = TxHash::random();
        let signer = PrivateKeySigner::random();
        let addr = signer.address();

        let expected_sig = signer.sign_hash(&hash).await.unwrap();
        headers
            .insert(SIGNATURE_HEADER, format!("{addr}:{}", expected_sig.to_hex()).parse().unwrap());

        let (address, signature) = auth_from_headers(&headers).unwrap();
        assert_eq!(signature, expected_sig);
        assert_eq!(address, addr);
    }
}
