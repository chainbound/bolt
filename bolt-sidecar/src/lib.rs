#![doc = include_str!("../README.md")]
#![warn(missing_debug_implementations, missing_docs, rustdoc::all)]
#![deny(unused_must_use, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod api;
mod client;
mod common;
mod crypto;
mod primitives;
mod state;
mod template;

/// Configuration and command-line argument parsing for the sidecar
pub mod config;

/// JSON-RPC server and handlers for the sidecar
pub mod json_rpc;

pub use api::builder::{start_builder_proxy, BuilderProxyConfig};
