use std::{
    collections::HashSet,
    fmt,
    future::Future,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    str::FromStr,
    sync::Arc,
};

use alloy::primitives::{Address, Signature};
use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use axum_extra::extract::WithRejection;
use serde_json::Value;
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
};
use tracing::{debug, error, info, instrument};

use crate::{
    commitments::handlers,
    common::CARGO_PKG_VERSION,
    primitives::{
        commitment::{InclusionCommitment, SignedCommitment},
        CommitmentRequest, InclusionRequest,
    },
};

use super::{
    jsonrpc::{JsonPayload, JsonResponse},
    spec::{Error, SIGNATURE_HEADER},
};

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
    let sig = Signature::from_str(sig)
        .map_err(|_| Error::InvalidSignature(crate::primitives::SignatureError))?;

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
