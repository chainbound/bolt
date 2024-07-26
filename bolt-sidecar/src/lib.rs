#![doc = include_str!("../README.md")]
#![warn(missing_debug_implementations, missing_docs, rustdoc::all)]
#![deny(unused_must_use, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

/// All APIs in use by the sidecar.
mod api;
pub use api::{
    builder::{start_builder_proxy_server, BuilderProxyConfig},
    commitments,
    spec::{BuilderApi, ConstraintsApi},
};

mod client;
pub use client::{mevboost::MevBoostClient, rpc::RpcClient, BeaconClient};

/// Common types and compatibility utilities
/// (To be refactored)
mod common;

/// Functionality for building local block templates that can
/// be used as a fallback for proposers. It's also used to keep
/// any intermediary state that is needed to simulate EVM execution
pub mod builder;
pub use builder::LocalBuilder;

/// Configuration and command-line argument parsing
mod config;
pub use config::{ChainConfig, Config, Opts};

/// Crypto utilities, including BLS and ECDSA
pub mod crypto;

/// Primitive types and utilities
pub mod primitives;

/// State management and fetching for EVM simulation
pub mod state;

/// Utilities for testing
#[cfg(test)]
mod test_util;
