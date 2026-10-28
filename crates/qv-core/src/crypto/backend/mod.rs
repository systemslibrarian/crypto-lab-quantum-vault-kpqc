//! Concrete crypto backends.
//!
//! | Module       | Always compiled | Feature flag required for KpqC |
//! |--------------|-----------------|-------------------------------|
//! | [`dev`]      | No              | `dev-backend` only |
//! | [`kpqc`]     | Yes (stub only) | `kpqc-native` for native crypto; `kpqc-wasm` remains an error-only scaffold |
//! | [`kpqc_ffi`] | No              | `kpqc-native` only |
//!
//! The `dev` module is omitted unless `dev-backend` is enabled. The `kpqc`
//! module is always compiled: without a KpqC feature flag
//! its methods return explicit `NotAvailable` errors.

#[cfg(feature = "dev-backend")]
pub mod dev;
pub mod kpqc;

#[cfg(feature = "kpqc-native")]
pub mod kpqc_ffi;

#[cfg(feature = "dev-backend")]
pub use dev::{DevKem, DevSignature};
pub use kpqc::{KpqcKem, KpqcSignature};
