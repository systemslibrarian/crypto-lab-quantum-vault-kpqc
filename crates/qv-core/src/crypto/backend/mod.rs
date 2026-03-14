//! Concrete crypto backends.
//!
//! | Module       | Always compiled | Feature flag required for KpqC |
//! |--------------|-----------------|-------------------------------|
//! | [`dev`]      | Yes             | — (dev backend is always available) |
//! | [`kpqc`]     | Yes (stub only) | `kpqc-native` or `kpqc-wasm` for real crypto |
//! | [`kpqc_ffi`] | No              | `kpqc-native` only |
//!
//! The `dev-backend` feature flag exists in `Cargo.toml` to allow future
//! conditional compilation, but `dev.rs` is currently always compiled.
//! The `kpqc` module is always compiled too: without a KpqC feature flag
//! its methods return explicit `NotAvailable` errors.

pub mod dev;
pub mod kpqc;

#[cfg(feature = "kpqc-native")]
pub mod kpqc_ffi;

pub use dev::{DevKem, DevSignature};
pub use kpqc::{KpqcKem, KpqcSignature};
