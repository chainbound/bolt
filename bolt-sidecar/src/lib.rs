#![doc = include_str!("../README.md")]
#![warn(missing_debug_implementations, missing_docs, rustdoc::all)]
#![deny(unused_must_use, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod client;
mod common;
mod crypto;
mod pubsub;
mod state;
mod template;
mod types;

/// Configuration and command-line argument parsing for the sidecar
pub mod config;

/// JSON-RPC server and handlers for the sidecar
pub mod json_rpc;
