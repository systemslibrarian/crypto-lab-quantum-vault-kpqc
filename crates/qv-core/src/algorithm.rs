// SPDX-License-Identifier: MIT
//! Algorithm registry for Quantum Vault.
//!
//! This module provides **centralized, fail-closed** validation of all
//! cryptographic algorithm identifiers. Every algorithm ID in the crate
//! must be registered here.
//!
//! # Security Model
//!
//! - **Fail-closed**: Unknown algorithm IDs are rejected by default.
//! - **Enum-based**: Algorithm variants are compile-time constants.
//! - **Single source of truth**: All algorithm string IDs are defined once.
//!
//! # Adding New Algorithms
//!
//! 1. Add a variant to the appropriate enum ([`KemAlgorithm`], [`SignatureAlgorithm`], etc.).
//! 2. Update the `from_id`, `as_str`, and `Display` implementations.
//! 3. Update any `const` assertions as needed.
//! 4. Update the container parser if this affects container format.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// KEM Algorithms
// ─────────────────────────────────────────────────────────────────────────────

/// Key Encapsulation Mechanism (KEM) algorithm identifiers.
///
/// # SECURITY INVARIANT
/// All KEM algorithm IDs used anywhere in the crate MUST be defined here.
/// The `from_id` method is **fail-closed**: unknown IDs return `None`.
///
/// # Supported Algorithms
///
/// | ID | Description | Security Level |
/// |----|-------------|----------------|
/// | `SMAUG-T-3` | SMAUG-T Level 3 (KPQC Round 4) | AES-192 equivalent |
/// | `dev-kem` | Development-only stub KEM | **NONE - TESTING ONLY** |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KemAlgorithm {
    /// SMAUG-T Level 3 — lattice-based KEM from KPQC Round 4.
    ///
    /// This is the production KEM. It provides IND-CCA2 security against
    /// quantum adversaries at approximately AES-192 equivalent security.
    SmaugT3,

    /// Development-only stub KEM for testing.
    ///
    /// # Warning
    /// This provides **NO SECURITY** and must never be used in production.
    /// It exists only to allow testing without the KPQC FFI dependencies.
    #[cfg(feature = "dev-backend")]
    DevKem,
}

impl KemAlgorithm {
    /// Algorithm ID for SMAUG-T Level 3.
    pub const SMAUG_T_3_ID: &'static str = "SMAUG-T-3";

    /// Algorithm ID for development KEM (feature-gated).
    #[cfg(feature = "dev-backend")]
    pub const DEV_KEM_ID: &'static str = "dev-kem";

    /// Parse an algorithm ID string into a [`KemAlgorithm`].
    ///
    /// # Returns
    /// - `Some(algorithm)` if the ID is recognized.
    /// - `None` if the ID is unknown (**fail-closed**).
    ///
    /// # Example
    /// ```
    /// use qv_core::algorithm::KemAlgorithm;
    ///
    /// assert_eq!(
    ///     KemAlgorithm::from_id("SMAUG-T-3"),
    ///     Some(KemAlgorithm::SmaugT3)
    /// );
    /// assert_eq!(KemAlgorithm::from_id("unknown"), None);
    /// ```
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            Self::SMAUG_T_3_ID => Some(Self::SmaugT3),
            #[cfg(feature = "dev-backend")]
            Self::DEV_KEM_ID => Some(Self::DevKem),
            _ => None, // SECURITY: fail-closed — reject unknown algorithms
        }
    }

    /// Returns the canonical string identifier for this algorithm.
    ///
    /// This is the value stored in container files and used for validation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SmaugT3 => Self::SMAUG_T_3_ID,
            #[cfg(feature = "dev-backend")]
            Self::DevKem => Self::DEV_KEM_ID,
        }
    }

    /// Returns whether this algorithm is safe for production use.
    ///
    /// Development algorithms return `false`.
    #[must_use]
    pub const fn is_production_safe(&self) -> bool {
        match self {
            Self::SmaugT3 => true,
            #[cfg(feature = "dev-backend")]
            Self::DevKem => false,
        }
    }

    /// Returns all supported KEM algorithm IDs.
    ///
    /// Useful for error messages and documentation.
    #[must_use]
    pub fn supported_ids() -> &'static [&'static str] {
        #[cfg(feature = "dev-backend")]
        {
            &[Self::SMAUG_T_3_ID, Self::DEV_KEM_ID]
        }
        #[cfg(not(feature = "dev-backend"))]
        {
            &[Self::SMAUG_T_3_ID]
        }
    }
}

impl fmt::Display for KemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature Algorithms
// ─────────────────────────────────────────────────────────────────────────────

/// Digital signature algorithm identifiers.
///
/// # SECURITY INVARIANT
/// All signature algorithm IDs used anywhere in the crate MUST be defined here.
/// The `from_id` method is **fail-closed**: unknown IDs return `None`.
///
/// # Supported Algorithms
///
/// | ID | Description | Security Level |
/// |----|-------------|----------------|
/// | `HAETAE-3` | HAETAE Level 3 (KPQC Round 4) | AES-192 equivalent |
/// | `dev-sig` | Development-only stub signature | **NONE - TESTING ONLY** |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// HAETAE Level 3 — lattice-based signature from KPQC Round 4.
    ///
    /// This is the production signature scheme. It provides EUF-CMA security
    /// against quantum adversaries at approximately AES-192 equivalent security.
    Haetae3,

    /// Development-only stub signature for testing.
    ///
    /// # Warning
    /// This provides **NO SECURITY** and must never be used in production.
    /// It exists only to allow testing without the KPQC FFI dependencies.
    #[cfg(feature = "dev-backend")]
    DevSig,
}

impl SignatureAlgorithm {
    /// Algorithm ID for HAETAE Level 3.
    pub const HAETAE_3_ID: &'static str = "HAETAE-3";

    /// Algorithm ID for development signature (feature-gated).
    #[cfg(feature = "dev-backend")]
    pub const DEV_SIG_ID: &'static str = "dev-sig";

    /// Parse an algorithm ID string into a [`SignatureAlgorithm`].
    ///
    /// # Returns
    /// - `Some(algorithm)` if the ID is recognized.
    /// - `None` if the ID is unknown (**fail-closed**).
    ///
    /// # Example
    /// ```
    /// use qv_core::algorithm::SignatureAlgorithm;
    ///
    /// assert_eq!(
    ///     SignatureAlgorithm::from_id("HAETAE-3"),
    ///     Some(SignatureAlgorithm::Haetae3)
    /// );
    /// assert_eq!(SignatureAlgorithm::from_id("unknown"), None);
    /// ```
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            Self::HAETAE_3_ID => Some(Self::Haetae3),
            #[cfg(feature = "dev-backend")]
            Self::DEV_SIG_ID => Some(Self::DevSig),
            _ => None, // SECURITY: fail-closed — reject unknown algorithms
        }
    }

    /// Returns the canonical string identifier for this algorithm.
    ///
    /// This is the value stored in container files and used for validation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Haetae3 => Self::HAETAE_3_ID,
            #[cfg(feature = "dev-backend")]
            Self::DevSig => Self::DEV_SIG_ID,
        }
    }

    /// Returns whether this algorithm is safe for production use.
    ///
    /// Development algorithms return `false`.
    #[must_use]
    pub const fn is_production_safe(&self) -> bool {
        match self {
            Self::Haetae3 => true,
            #[cfg(feature = "dev-backend")]
            Self::DevSig => false,
        }
    }

    /// Returns all supported signature algorithm IDs.
    ///
    /// Useful for error messages and documentation.
    #[must_use]
    pub fn supported_ids() -> &'static [&'static str] {
        #[cfg(feature = "dev-backend")]
        {
            &[Self::HAETAE_3_ID, Self::DEV_SIG_ID]
        }
        #[cfg(not(feature = "dev-backend"))]
        {
            &[Self::HAETAE_3_ID]
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AEAD Algorithms
// ─────────────────────────────────────────────────────────────────────────────

/// Authenticated Encryption with Associated Data (AEAD) algorithm identifiers.
///
/// # SECURITY INVARIANT
/// All AEAD algorithm IDs used anywhere in the crate MUST be defined here.
/// The `from_id` method is **fail-closed**: unknown IDs return `None`.
///
/// # Supported Algorithms
///
/// | ID | Description | Security Level |
/// |----|-------------|----------------|
/// | `AES-256-GCM` | AES-256 in GCM mode (96-bit nonce, 128-bit tag) | AES-256 |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AeadAlgorithm {
    /// AES-256 in Galois/Counter Mode.
    ///
    /// Parameters:
    /// - Key: 256 bits (32 bytes)
    /// - Nonce: 96 bits (12 bytes)
    /// - Tag: 128 bits (16 bytes)
    ///
    /// This is the only supported AEAD algorithm. It provides confidentiality
    /// and integrity for the encrypted payload.
    Aes256Gcm,
}

impl AeadAlgorithm {
    /// Algorithm ID for AES-256-GCM.
    pub const AES_256_GCM_ID: &'static str = "AES-256-GCM";

    /// Parse an algorithm ID string into an [`AeadAlgorithm`].
    ///
    /// # Returns
    /// - `Some(algorithm)` if the ID is recognized.
    /// - `None` if the ID is unknown (**fail-closed**).
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            Self::AES_256_GCM_ID => Some(Self::Aes256Gcm),
            _ => None, // SECURITY: fail-closed — reject unknown algorithms
        }
    }

    /// Returns the canonical string identifier for this algorithm.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => Self::AES_256_GCM_ID,
        }
    }

    /// Returns all supported AEAD algorithm IDs.
    #[must_use]
    pub fn supported_ids() -> &'static [&'static str] {
        &[Self::AES_256_GCM_ID]
    }
}

impl fmt::Display for AeadAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience: Check if algorithm ID is supported (fail-closed)
// ─────────────────────────────────────────────────────────────────────────────

/// Check if a KEM algorithm ID is supported.
///
/// # SECURITY INVARIANT
/// This function is **fail-closed**: it returns `false` for any unknown ID.
/// All container parsing MUST use this function to validate KEM algorithm IDs.
#[inline]
#[must_use]
pub fn is_supported_kem(id: &str) -> bool {
    KemAlgorithm::from_id(id).is_some()
}

/// Check if a signature algorithm ID is supported.
///
/// # SECURITY INVARIANT
/// This function is **fail-closed**: it returns `false` for any unknown ID.
/// All container parsing MUST use this function to validate signature algorithm IDs.
#[inline]
#[must_use]
pub fn is_supported_signature(id: &str) -> bool {
    SignatureAlgorithm::from_id(id).is_some()
}

/// Check if an AEAD algorithm ID is supported.
///
/// # SECURITY INVARIANT
/// This function is **fail-closed**: it returns `false` for any unknown ID.
#[inline]
#[must_use]
pub fn is_supported_aead(id: &str) -> bool {
    AeadAlgorithm::from_id(id).is_some()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── KEM Algorithm Tests ──────────────────────────────────────────────────

    #[test]
    fn kem_roundtrip_smaug() {
        let alg = KemAlgorithm::SmaugT3;
        assert_eq!(alg.as_str(), "SMAUG-T-3");
        assert_eq!(KemAlgorithm::from_id("SMAUG-T-3"), Some(alg));
        assert!(alg.is_production_safe());
    }

    #[cfg(feature = "dev-backend")]
    #[test]
    fn kem_roundtrip_dev() {
        let alg = KemAlgorithm::DevKem;
        assert_eq!(alg.as_str(), "dev-kem");
        assert_eq!(KemAlgorithm::from_id("dev-kem"), Some(alg));
        assert!(!alg.is_production_safe());
    }

    #[test]
    fn kem_unknown_fails() {
        assert_eq!(KemAlgorithm::from_id("unknown"), None);
        assert_eq!(KemAlgorithm::from_id("SMAUG-T-5"), None);
        assert_eq!(KemAlgorithm::from_id(""), None);
        assert_eq!(KemAlgorithm::from_id("smaug-t-3"), None); // case-sensitive
    }

    #[test]
    fn kem_is_supported() {
        assert!(is_supported_kem("SMAUG-T-3"));
        assert!(!is_supported_kem("unknown"));
        assert!(!is_supported_kem(""));
    }

    // ── Signature Algorithm Tests ────────────────────────────────────────────

    #[test]
    fn sig_roundtrip_haetae() {
        let alg = SignatureAlgorithm::Haetae3;
        assert_eq!(alg.as_str(), "HAETAE-3");
        assert_eq!(SignatureAlgorithm::from_id("HAETAE-3"), Some(alg));
        assert!(alg.is_production_safe());
    }

    #[cfg(feature = "dev-backend")]
    #[test]
    fn sig_roundtrip_dev() {
        let alg = SignatureAlgorithm::DevSig;
        assert_eq!(alg.as_str(), "dev-sig");
        assert_eq!(SignatureAlgorithm::from_id("dev-sig"), Some(alg));
        assert!(!alg.is_production_safe());
    }

    #[test]
    fn sig_unknown_fails() {
        assert_eq!(SignatureAlgorithm::from_id("unknown"), None);
        assert_eq!(SignatureAlgorithm::from_id("HAETAE-5"), None);
        assert_eq!(SignatureAlgorithm::from_id(""), None);
        assert_eq!(SignatureAlgorithm::from_id("haetae-3"), None); // case-sensitive
    }

    #[test]
    fn sig_is_supported() {
        assert!(is_supported_signature("HAETAE-3"));
        assert!(!is_supported_signature("unknown"));
        assert!(!is_supported_signature(""));
    }

    // ── AEAD Algorithm Tests ─────────────────────────────────────────────────

    #[test]
    fn aead_roundtrip() {
        let alg = AeadAlgorithm::Aes256Gcm;
        assert_eq!(alg.as_str(), "AES-256-GCM");
        assert_eq!(AeadAlgorithm::from_id("AES-256-GCM"), Some(alg));
    }

    #[test]
    fn aead_unknown_fails() {
        assert_eq!(AeadAlgorithm::from_id("AES-128-GCM"), None);
        assert_eq!(AeadAlgorithm::from_id("ChaCha20-Poly1305"), None);
        assert_eq!(AeadAlgorithm::from_id(""), None);
    }

    #[test]
    fn aead_is_supported() {
        assert!(is_supported_aead("AES-256-GCM"));
        assert!(!is_supported_aead("unknown"));
    }

    // ── Display Tests ────────────────────────────────────────────────────────

    #[test]
    fn display_implementations() {
        assert_eq!(format!("{}", KemAlgorithm::SmaugT3), "SMAUG-T-3");
        assert_eq!(format!("{}", SignatureAlgorithm::Haetae3), "HAETAE-3");
        assert_eq!(format!("{}", AeadAlgorithm::Aes256Gcm), "AES-256-GCM");
    }

    // ── Supported IDs Tests ──────────────────────────────────────────────────

    #[test]
    fn supported_ids_are_valid() {
        for &id in KemAlgorithm::supported_ids() {
            assert!(KemAlgorithm::from_id(id).is_some(), "KEM ID '{id}' should be valid");
        }
        for &id in SignatureAlgorithm::supported_ids() {
            assert!(SignatureAlgorithm::from_id(id).is_some(), "Sig ID '{id}' should be valid");
        }
        for &id in AeadAlgorithm::supported_ids() {
            assert!(AeadAlgorithm::from_id(id).is_some(), "AEAD ID '{id}' should be valid");
        }
    }
}
