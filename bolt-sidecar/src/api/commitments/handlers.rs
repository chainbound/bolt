use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request},
    response::Html,
    Json,
};
use axum_extra::extract::WithRejection;
use serde_json::Value;
use tracing::{debug, error, info, instrument};

use crate::{
    commitments::headers::auth_from_headers, common::CARGO_PKG_VERSION,
    primitives::InclusionRequest,
};

use super::{
    jsonrpc::{JsonPayload, JsonResponse},
    server::CommitmentsApiInner,
    spec::{CommitmentsApi, Error, RejectionError, GET_VERSION_METHOD, REQUEST_INCLUSION_METHOD},
};

/// Handler function for the root JSON-RPC path.
#[instrument(skip_all, name = "POST /rpc", fields(method = %payload.method))]
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

/// Not found fallback handler for all non-matched routes.
///
/// This handler returns a simple 404 page.
#[instrument(skip_all, name = "not_found")]
pub async fn not_found(req: Request<Body>) -> Html<&'static str> {
    error!(uri = ?req.uri(), "Route not found");
    Html("404 - Not Found")
}

/// Status handler
#[instrument(skip_all, name = "GET /status")]
pub async fn status() -> Html<&'static str> {
    Html("OK")
}
