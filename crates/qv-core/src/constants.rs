// SPDX-License-Identifier: MIT
//! Security-critical constants for Quantum Vault.
//!
//! All size limits, version numbers, and algorithm identifiers are centralized
//! here to simplify auditing. Changes to these values may have security
//! implications and should be reviewed carefully.

// ---------------------------------------------------------------------------
// Container Format
// ---------------------------------------------------------------------------

/// Magic string identifying the container format.
///
/// SECURITY INVARIANT: Must be checked before any parsing to fail-closed
/// on unknown formats.
pub const MAGIC: &str = "QVKP";

/// Current container format version.
///
/// SECURITY INVARIANT: Unknown versions are rejected fail-closed.
pub const CONTAINER_VERSION: u8 = 2;

// ---------------------------------------------------------------------------
// Size Limits
// ---------------------------------------------------------------------------

/// Maximum size of a serialized container (8 MiB).
///
/// SECURITY INVARIANT: Enforced during parsing to prevent memory exhaustion.
pub const MAX_CONTAINER_BYTES: usize = 8 * 1024 * 1024;

/// Maximum number of Shamir shares allowed.
///
/// SECURITY INVARIANT: Limits enumeration attack surface and memory usage.
pub const MAX_SHARE_COUNT: u8 = 16;

/// Maximum size of the encrypted payload (4 MiB).
pub const MAX_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;

/// Maximum size of a signature.
///
/// SECURITY INVARIANT: HAETAE Mode 2 signatures are at most 1474 bytes;
/// 4096 provides headroom for future algorithms.
pub const MAX_SIGNATURE_BYTES: usize = 4096;

/// Maximum size of a KEM ciphertext per share.
///
/// SECURITY INVARIANT: SMAUG-T Level 3 ciphertexts are ~1024 bytes;
/// 2048 provides headroom.
pub const MAX_KEM_CIPHERTEXT_BYTES: usize = 2048;

/// Maximum size of an encrypted share.
///
/// SECURITY INVARIANT: A 256-bit key share plus AEAD overhead should not
/// exceed 128 bytes.
pub const MAX_ENCRYPTED_SHARE_BYTES: usize = 128;

/// Maximum length of an algorithm identifier string.
pub const MAX_ALGORITHM_ID_BYTES: usize = 32;

/// Fixed size of the container identifier.
pub const CONTAINER_ID_BYTES: usize = 16;

// ---------------------------------------------------------------------------
// AEAD Parameters
// ---------------------------------------------------------------------------

/// AES-256-GCM nonce size in bytes.
pub const AES_GCM_NONCE_BYTES: usize = 12;

/// AES-256-GCM tag size in bytes.
pub const AES_GCM_TAG_BYTES: usize = 16;

/// AES-256 key size in bytes.
pub const AES_KEY_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Shamir Parameters
// ---------------------------------------------------------------------------

/// Minimum shares required for reconstruction (threshold floor).
///
/// SECURITY INVARIANT: Single-share schemes are rejected to ensure
/// meaningful threshold security.
pub const MIN_THRESHOLD: u8 = 2;

// ---------------------------------------------------------------------------
// HKDF Domain Separation Labels
// ---------------------------------------------------------------------------

/// HKDF salt used for all key derivations.
///
/// SECURITY INVARIANT: Version-specific salt prevents cross-version
/// key confusion if format is ever upgraded.
pub const HKDF_SALT: &[u8] = b"qvault-v2";

/// HKDF info label for deriving the outer container nonce.
pub const HKDF_LABEL_CONTAINER_NONCE: &[u8] = b"qvault-container-nonce";

/// HKDF info label for deriving share encryption keys.
///
/// SECURITY INVARIANT: This label must be unique across all HKDF uses
/// in the system to prevent cross-context key reuse.
pub const HKDF_LABEL_SHARE_KEY: &[u8] = b"qvault-share-key";

/// HKDF info label for deriving share encryption nonces.
pub const HKDF_LABEL_SHARE_NONCE: &[u8] = b"qvault-share-nonce";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_sane() {
        assert_eq!(MAGIC, "QVKP");
        assert_eq!(CONTAINER_VERSION, 2);
        assert!(MAX_CONTAINER_BYTES >= MAX_CIPHERTEXT_BYTES);
        assert!(MAX_ENCRYPTED_SHARE_BYTES > AES_KEY_BYTES + AES_GCM_TAG_BYTES);
        assert!(MIN_THRESHOLD >= 2);
    }

    #[test]
    fn hkdf_labels_are_distinct() {
        assert_ne!(HKDF_LABEL_SHARE_KEY, HKDF_LABEL_SHARE_NONCE);
        assert_ne!(HKDF_LABEL_SHARE_KEY, HKDF_LABEL_CONTAINER_NONCE);
        assert_ne!(HKDF_LABEL_SHARE_NONCE, HKDF_LABEL_CONTAINER_NONCE);
    }
}
