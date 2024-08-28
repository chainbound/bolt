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
    commitments::headers::auth_from_headers,
    common::CARGO_PKG_VERSION,
    primitives::{
        commitment::{InclusionCommitment, SignedCommitment},
        CommitmentRequest, InclusionRequest,
    },
};

use super::{
    jsonrpc::{JsonPayload, JsonResponse},
    server::CommitmentsApiInner,
    spec::{
        CommitmentsApi, Error, RejectionError, GET_VERSION_METHOD, REQUEST_INCLUSION_METHOD,
        SIGNATURE_HEADER,
    },
};

/// Handler function for the root JSON-RPC path.
#[instrument(skip_all, name = "RPC", fields(method = %payload.method))]
pub async fn rpc_entrypoint(
    headers: HeaderMap,
    State(api): State<Arc<CommitmentsApiInner>>,
    WithRejection(Json(payload), _): WithRejection<Json<JsonPayload>, Error>,
) -> Result<Json<JsonResponse>, Error> {
    debug!("Received new request");

    let (signer, signature) = auth_from_headers(&headers).inspect_err(|e| {
        error!("Failed to extract signature from headers: {:?}", e);
    })?;

    match payload.method.as_str() {
        GET_VERSION_METHOD => {
            let version_string = format!("bolt-sidecar-v{CARGO_PKG_VERSION}");
            Ok(Json(JsonResponse {
                id: payload.id,
                result: Value::String(version_string),
                ..Default::default()
            }))
        }

        REQUEST_INCLUSION_METHOD => {
            let Some(request_json) = payload.params.first().cloned() else {
                return Err(RejectionError::ValidationFailed("Bad params".to_string()).into());
            };

            // Parse the inclusion request from the parameters
            let mut inclusion_request: InclusionRequest = serde_json::from_value(request_json)
                .map_err(|e| RejectionError::ValidationFailed(e.to_string()))?;

            // Set the signature here for later processing
            inclusion_request.set_signature(signature);

            let digest = inclusion_request.digest();
            let recovered_signer = signature.recover_address_from_prehash(&digest)?;

            if recovered_signer != signer {
                error!(
                    ?recovered_signer,
                    ?signer,
                    "Recovered signer does not match the provided signer"
                );

                return Err(Error::InvalidSignature(crate::primitives::SignatureError));
            }

            // Set the request signer
            inclusion_request.set_signer(recovered_signer);

            info!(signer = ?recovered_signer, %digest, "New valid inclusion request received");
            let inclusion_commitment = api.request_inclusion(inclusion_request).await?;

            // Create the JSON-RPC response
            let response = JsonResponse {
                id: payload.id,
                result: serde_json::to_value(inclusion_commitment).unwrap(),
                ..Default::default()
            };

            Ok(Json(response))
        }
        other => {
            error!("Unknown method: {}", other);
            Err(Error::UnknownMethod)
        }
    }
}
