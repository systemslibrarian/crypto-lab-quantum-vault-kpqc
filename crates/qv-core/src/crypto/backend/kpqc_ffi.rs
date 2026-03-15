//! FFI boundary between Rust and the SMAUG-T / HAETAE C reference
//! implementations.
//!
//! This module is only compiled when the `kpqc-native` feature is active.
//! Every symbol in the `extern "C"` block must be resolved at link time by the
//! static libraries produced by `build.rs`.
//!
//! # Safety
//!
//! All public functions in this module are safe Rust wrappers.  The unsafe
//! `extern "C"` calls are encapsulated here and nowhere else.  Callers may
//! rely on these wrappers to:
//! - correctly size output buffers (see the SIZE constants below),
//! - convert C integer return codes to `anyhow::Result`, and
//! - validate input lengths before invoking C functions.
//!
//! # Parameter sizes
//!
//! All sizes are for security Level 3 (SMAUGT_MODE3 / HAETAE_MODE3).
//! They are derived directly from the reference-implementation headers:
//!
//! | Constant                  | Value | Source                                  |
//! |---------------------------|-------|-----------------------------------------|
//! | `SMAUG_T_PK_BYTES`        | 1088  | params.h K=3 formula                    |
//! | `SMAUG_T_SK_BYTES`        | 1312  | params.h K=3 formula                    |
//! | `SMAUG_T_CT_BYTES`        | 992   | params.h K=3 formula                    |
//! | `SMAUG_T_SS_BYTES`        | 32    | all levels                              |
//! | `HAETAE_PK_BYTES`         | 1472  | 32 + 3*480                              |
//! | `HAETAE_SK_BYTES`         | 2112  | 1472 + 5*64 + 3*96 + 32                 |
//! | `HAETAE_SIG_BYTES`        | 2349  | HAETAE_CRYPTO_BYTES for mode3           |

#![allow(non_snake_case, non_upper_case_globals)]

use anyhow::{anyhow, Result};

// ---------------------------------------------------------------------------
// Parameter sizes — SMAUG-T Level 3 (SMAUGT_MODE3)
// Derived from vendor/smaug-t/SMAUG-T-1.1.1/reference_implementation/include/params.h
// K=3, LOG_Q=11, LOG_P=9, LOG_P_PRIME=4, N=256
//   PK  = PKSEED(32) + K*LOG_Q*N/8 = 32 + 3*352 = 1088
//   SK  = SKPOLYVEC(K*N/4) + T_BYTES(32) + PK = 192 + 32 + 1088 = 1312
//   CT  = K*LOG_P*N/8 + LOG_P_PRIME*N/8 = 864 + 128 = 992
// ---------------------------------------------------------------------------

pub const SMAUG_T_PK_BYTES: usize = 1088;
pub const SMAUG_T_SK_BYTES: usize = 1312;
pub const SMAUG_T_CT_BYTES: usize = 992;
pub const SMAUG_T_SS_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Parameter sizes — HAETAE Level 3 (HAETAE_MODE3)
// Derived from vendor/haetae/HAETAE-1.1.2/reference_implementation/include/params.h
// K=3, L=6, M=L-1=5, POLY_Q_PACKED=480, POLYETA_PACKED=64, POLY2ETA_PACKED=96
//   PK  = SEEDBYTES(32) + K*POLYQ_PACKED = 32 + 3*480 = 1472
//   SK  = PK + M*POLYETA_PACKED + K*POLY2ETA_PACKED + SEEDBYTES
//       = 1472 + 5*64 + 3*96 + 32 = 2112
//   SIG = HAETAE_CRYPTO_BYTES for mode3 = 2349
// ---------------------------------------------------------------------------

pub const HAETAE_PK_BYTES: usize = 1472;
pub const HAETAE_SK_BYTES: usize = 2112;
/// Maximum signature size for HAETAE Level 3.
pub const HAETAE_SIG_BYTES: usize = 2349;

// ---------------------------------------------------------------------------
// Raw extern "C" declarations
//
// Symbol names are constructed by the reference implementation's namespace
// macro: SMAUGT_CONFIG_NAMESPACE_PREFIX_MODE = cryptolab_smaugt_mode3_
// and HAETAE_CONFIG_NAMESPACE_PREFIX_MODE = cryptolab_haetae_mode3_
// These come from config.h when compiled with the mode3 defines.
// ---------------------------------------------------------------------------

extern "C" {
    // ── SMAUG-T (cryptolab_smaugt_mode3_ prefix) ─────────────────────────

    /// `pk` >= SMAUG_T_PK_BYTES; `sk` >= SMAUG_T_SK_BYTES. Returns 0 on success.
    fn cryptolab_smaugt_mode3_keypair(pk: *mut u8, sk: *mut u8) -> std::os::raw::c_int;

    /// `ct` >= SMAUG_T_CT_BYTES; `ss` >= SMAUG_T_SS_BYTES; `pk` = SMAUG_T_PK_BYTES.
    /// Returns 0 on success.
    fn cryptolab_smaugt_mode3_enc(
        ct: *mut u8,
        ss: *mut u8,
        pk: *const u8,
    ) -> std::os::raw::c_int;

    /// `ss` >= SMAUG_T_SS_BYTES; `ct` = SMAUG_T_CT_BYTES; `sk` = SMAUG_T_SK_BYTES.
    /// Returns 0 on success.
    fn cryptolab_smaugt_mode3_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> std::os::raw::c_int;

    // ── HAETAE (cryptolab_haetae_mode3_ prefix) ───────────────────────────

    /// `vk` >= HAETAE_PK_BYTES; `sk` >= HAETAE_SK_BYTES. Returns 0 on success.
    fn cryptolab_haetae_mode3_keypair(vk: *mut u8, sk: *mut u8) -> std::os::raw::c_int;

    /// Sign `mlen` bytes at `m` using secret key `sk`.
    ///
    /// `ctx` / `ctxlen`: signing context (pass null / 0 for no context).
    /// `sig` must be >= HAETAE_SIG_BYTES. `*siglen` receives the actual length written.
    /// Returns 0 on success.
    fn cryptolab_haetae_mode3_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        sk: *const u8,
    ) -> std::os::raw::c_int;

    /// Verify a HAETAE signature.
    ///
    /// `ctx` / `ctxlen`: signing context (pass null / 0 for no context).
    /// Returns 0 when the signature is valid.
    fn cryptolab_haetae_mode3_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        ctx: *const u8,
        ctxlen: usize,
        vk: *const u8,
    ) -> std::os::raw::c_int;
}

// ---------------------------------------------------------------------------
// Safe Rust wrappers — SMAUG-T
// ---------------------------------------------------------------------------

/// Generate a SMAUG-T Level-3 keypair. Returns `(public_key, secret_key)`.
pub fn smaug_t_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut pk = vec![0u8; SMAUG_T_PK_BYTES];
    let mut sk = vec![0u8; SMAUG_T_SK_BYTES];
    let rc = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        cryptolab_smaugt_mode3_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
    }))
    .map_err(|_| anyhow!("SMAUG-T keygen panicked at FFI boundary"))?;
    if rc != 0 {
        return Err(anyhow!("cryptolab_smaugt_mode3_keypair failed with code {rc}"));
    }
    Ok((pk, sk))
}

/// Encapsulate using a SMAUG-T Level-3 public key.
/// Returns `(ciphertext, shared_secret)`.
pub fn smaug_t_enc(pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if pk.len() != SMAUG_T_PK_BYTES {
        return Err(anyhow!(
            "SMAUG-T public key must be {SMAUG_T_PK_BYTES} bytes, got {}",
            pk.len()
        ));
    }
    let mut ct = vec![0u8; SMAUG_T_CT_BYTES];
    let mut ss = vec![0u8; SMAUG_T_SS_BYTES];
    let rc = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        cryptolab_smaugt_mode3_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr())
    }))
    .map_err(|_| anyhow!("SMAUG-T encapsulate panicked at FFI boundary"))?;
    if rc != 0 {
        return Err(anyhow!("cryptolab_smaugt_mode3_enc failed with code {rc}"));
    }
    Ok((ct, ss))
}

/// Decapsulate using a SMAUG-T Level-3 secret key + ciphertext.
/// Returns the shared secret.
pub fn smaug_t_dec(sk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    if sk.len() != SMAUG_T_SK_BYTES {
        return Err(anyhow!(
            "SMAUG-T secret key must be {SMAUG_T_SK_BYTES} bytes, got {}",
            sk.len()
        ));
    }
    if ct.len() != SMAUG_T_CT_BYTES {
        return Err(anyhow!(
            "SMAUG-T ciphertext must be {SMAUG_T_CT_BYTES} bytes, got {}",
            ct.len()
        ));
    }
    let mut ss = vec![0u8; SMAUG_T_SS_BYTES];
    let rc = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        cryptolab_smaugt_mode3_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
    }))
    .map_err(|_| anyhow!("SMAUG-T decapsulate panicked at FFI boundary"))?;
    if rc != 0 {
        return Err(anyhow!("cryptolab_smaugt_mode3_dec failed with code {rc}"));
    }
    Ok(ss)
}

// ---------------------------------------------------------------------------
// Safe Rust wrappers — HAETAE
// ---------------------------------------------------------------------------

/// Generate a HAETAE Level-3 keypair. Returns `(public_key, secret_key)`.
pub fn haetae_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut pk = vec![0u8; HAETAE_PK_BYTES];
    let mut sk = vec![0u8; HAETAE_SK_BYTES];
    let rc = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        cryptolab_haetae_mode3_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
    }))
    .map_err(|_| anyhow!("HAETAE keygen panicked at FFI boundary"))?;
    if rc != 0 {
        return Err(anyhow!("cryptolab_haetae_mode3_keypair failed with code {rc}"));
    }
    Ok((pk, sk))
}

/// Sign `message` with a HAETAE Level-3 secret key.
/// Returns the signature bytes (length <= `HAETAE_SIG_BYTES`).
pub fn haetae_sign(sk: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    if sk.len() != HAETAE_SK_BYTES {
        return Err(anyhow!(
            "HAETAE secret key must be {HAETAE_SK_BYTES} bytes, got {}",
            sk.len()
        ));
    }
    let mut sig = vec![0u8; HAETAE_SIG_BYTES];
    let mut siglen: usize = HAETAE_SIG_BYTES;
    let rc = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        cryptolab_haetae_mode3_signature(
            sig.as_mut_ptr(),
            &mut siglen as *mut usize,
            message.as_ptr(),
            message.len(),
            std::ptr::null(), // ctx: no signing context
            0,                // ctxlen
            sk.as_ptr(),
        )
    }))
    .map_err(|_| anyhow!("HAETAE sign panicked at FFI boundary"))?;
    if rc != 0 {
        return Err(anyhow!("cryptolab_haetae_mode3_signature failed with code {rc}"));
    }
    // Defensive: a buggy C implementation could write siglen > HAETAE_SIG_BYTES,
    // in which case the buffer was already overrun, but we prevent a confusing
    // truncate-to-larger-length no-op from silently producing an over-long blob.
    if siglen > HAETAE_SIG_BYTES {
        return Err(anyhow!(
            "HAETAE signature length {siglen} exceeds allocated buffer {HAETAE_SIG_BYTES}"
        ));
    }
    sig.truncate(siglen);
    Ok(sig)
}

/// Verify a HAETAE Level-3 signature.
/// Returns `Ok(true)` when valid, `Ok(false)` when invalid.
pub fn haetae_verify(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    if pk.len() != HAETAE_PK_BYTES {
        return Err(anyhow!(
            "HAETAE public key must be {HAETAE_PK_BYTES} bytes, got {}",
            pk.len()
        ));
    }
    let rc = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        cryptolab_haetae_mode3_verify(
            signature.as_ptr(),
            signature.len(),
            message.as_ptr(),
            message.len(),
            std::ptr::null(), // ctx: no signing context
            0,                // ctxlen
            pk.as_ptr(),
        )
    }))
    .map_err(|_| anyhow!("HAETAE verify panicked at FFI boundary"))?;
    Ok(rc == 0)
}
