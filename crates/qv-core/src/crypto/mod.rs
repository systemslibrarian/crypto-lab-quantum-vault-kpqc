//! Pluggable cryptography abstraction layer.
//!
//! Concrete backends live in [`backend`]. The default `dev-backend` feature
//! enables [`backend::dev`] for development/testing only. Disabling that
//! feature removes the dev implementation from the crate. [`backend::kpqc`]
//! wires in SMAUG-T and HAETAE when the corresponding feature is enabled.

pub mod backend;
pub mod kem;
pub mod signature;

#[cfg(feature = "dev-backend")]
pub use backend::dev::{DevKem, DevSignature};
