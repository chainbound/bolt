use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use secp256k1::SecretKey;
use tokio::sync::mpsc;
use tracing::{error, info};
use warp::{http::Method, reject::Rejection, Filter};

mod api;
mod types;

use self::{
    api::{JsonRpcApi, PreconfirmationRpc},
    types::{JsonRpcError, JsonRpcRequest, JsonRpcResponse},
};

pub async fn start_server(port: u16, pk: Option<SecretKey>) -> eyre::Result<mpsc::Sender<()>> {
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    let cors = warp::cors().allow_any_origin().allow_method(Method::POST);

    let rpc_api = Arc::new(api::JsonRpcApi::new(pk));

    let rpc = warp::post()
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(warp::header::exact("content-type", "application/json"))
        .and(warp::any().map(move || Arc::clone(&rpc_api)))
        .and_then(handle_rpc_request)
        .and_then(|reply| async move { Ok::<_, Rejection>(warp::reply::json(&reply)) })
        .recover(handle_rejection)
        .with(cors);

    let (addr, server) =
        warp::serve(rpc).bind_with_graceful_shutdown(([0, 0, 0, 0], port), async move {
            shutdown_rx.recv().await;
        });

    tokio::spawn(server);
    info!("RPC HTTP server listening on http://{}", addr);

    Ok(shutdown_tx)
}

async fn handle_rpc_request(
    req_bytes: Bytes,
    rpc_api: Arc<JsonRpcApi>,
) -> Result<JsonRpcResponse, warp::Rejection> {
    let req = serde_json::from_slice::<JsonRpcRequest>(&req_bytes).map_err(|e| {
        error!(err = ?e, "failed parsing json rpc request");
        warp::reject::custom(JsonRpcError {
            code: -32700,
            message: "Request parse error".to_string(),
        })
    })?;

    tracing::debug!(?req, "received rpc request");

    let res = match req.method.as_str() {
        "eth_requestPreconfirmation" => rpc_api.request_preconfirmation(req.params).await?,
        _ => {
            error!(method = ?req.method, "RPC method not found");
            return Err(warp::reject::custom(JsonRpcError {
                code: -32601,
                message: format!("Method not found: {}", req.method),
            }));
        }
    };

    Ok(JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req.id,
        result: res,
    })
}

async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, Infallible> {
    if let Some(e) = err.find::<JsonRpcError>() {
        Ok(warp::reply::json(e))
    } else if err.is_not_found() {
        Ok(warp::reply::json(&JsonRpcError {
            code: -32601,
            message: "Resource not found".to_string(),
        }))
    } else if let Some(e) = err.find::<warp::reject::MissingHeader>() {
        Ok(warp::reply::json(&JsonRpcError {
            code: -32600,
            message: format!("Missing header: {}", e.name()),
        }))
    } else {
        error!(?err, "unhandled rejection");
        Ok(warp::reply::json(&JsonRpcError {
            code: -32000,
            message: "Internal error".to_string(),
        }))
    }
}
