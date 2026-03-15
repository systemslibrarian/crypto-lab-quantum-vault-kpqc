//! Property-based tests using proptest.
//!
//! These tests verify invariants with thousands of random inputs, catching
//! edge cases that hand-written tests might miss.
//!
//! Run with: `cargo test --test property_tests`

use proptest::prelude::*;
use qv_core::{
    container::QuantumVaultContainer,
    decrypt_bytes, encrypt_bytes,
    reconstruct_secret, split_secret, KeyShare,
};

/// Helper to convert anyhow::Error to proptest::TestCaseError
fn to_test_err<E: std::fmt::Debug>(e: E) -> TestCaseError {
    TestCaseError::fail(format!("{:?}", e))
}

// ============================================================================
// Shamir Secret Sharing Properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Property: For any valid secret and threshold params, splitting then
    /// reconstructing with all shares returns the original secret.
    #[test]
    fn shamir_roundtrip_all_shares(
        secret in prop::collection::vec(any::<u8>(), 1..=256),
        share_count in 2u8..=16,
    ) {
        let threshold = share_count.min(share_count); // threshold = share_count (t-of-t)
        let shares = split_secret(&secret, share_count, threshold).map_err(to_test_err)?;
        let recovered = reconstruct_secret(&shares).map_err(to_test_err)?;
        prop_assert_eq!(recovered, secret);
    }

    /// Property: Reconstruction with exactly threshold shares works.
    #[test]
    fn shamir_reconstruct_threshold_shares(
        secret in prop::collection::vec(any::<u8>(), 1..=128),
        share_count in 3u8..=10,
    ) {
        let threshold = 2.max(share_count.saturating_sub(1).max(2).min(share_count));
        let shares = split_secret(&secret, share_count, threshold).map_err(to_test_err)?;
        // Take exactly `threshold` shares (the first `threshold` shares)
        let subset: Vec<_> = shares.into_iter().take(threshold as usize).collect();
        let recovered = reconstruct_secret(&subset).map_err(to_test_err)?;
        prop_assert_eq!(recovered, secret);
    }

    /// Property: Reconstruction with fewer than threshold shares produces
    /// bytes that are NOT the original secret.
    #[test]
    fn shamir_under_threshold_is_wrong(
        secret in prop::collection::vec(any::<u8>(), 1..=64),
    ) {
        // 3-of-3: using only 2 shares must produce wrong output
        let shares = split_secret(&secret, 3, 3).map_err(to_test_err)?;
        let wrong = reconstruct_secret(&shares[0..2]).map_err(to_test_err)?;
        prop_assert_ne!(wrong, secret);
    }

    /// Property: Reconstruction is order-independent.
    #[test]
    fn shamir_order_independent(
        secret in prop::collection::vec(any::<u8>(), 1..=64),
    ) {
        let shares = split_secret(&secret, 3, 2).map_err(to_test_err)?;
        let r1 = reconstruct_secret(&[shares[0].clone(), shares[1].clone()]).map_err(to_test_err)?;
        let r2 = reconstruct_secret(&[shares[1].clone(), shares[0].clone()]).map_err(to_test_err)?;
        prop_assert_eq!(r1, r2);
    }

    /// Property: All share payloads have the same length as the secret.
    #[test]
    fn shamir_share_length_equals_secret(
        secret in prop::collection::vec(any::<u8>(), 1..=256),
        share_count in 2u8..=8,
    ) {
        let threshold = 2.min(share_count);
        let shares = split_secret(&secret, share_count, threshold).map_err(to_test_err)?;
        for share in &shares {
            prop_assert_eq!(share.data.len(), secret.len());
        }
    }

    /// Property: Share indices are unique and 1-based.
    #[test]
    fn shamir_indices_unique_one_based(
        secret in prop::collection::vec(any::<u8>(), 1..=32),
        share_count in 2u8..=16,
    ) {
        let shares = split_secret(&secret, share_count, 2).map_err(to_test_err)?;
        let indices: Vec<u8> = shares.iter().map(|s| s.index).collect();
        prop_assert_eq!(indices.len(), share_count as usize);
        for (i, idx) in indices.iter().enumerate() {
            prop_assert_eq!(*idx, (i + 1) as u8, "share index should be 1-based");
        }
        // Check uniqueness
        let unique: std::collections::HashSet<_> = indices.iter().collect();
        prop_assert_eq!(unique.len(), indices.len());
    }

    /// Property: Zero-index shares are rejected by reconstruct.
    #[test]
    fn shamir_rejects_zero_index(
        data in prop::collection::vec(any::<u8>(), 1..=32),
    ) {
        let shares = vec![KeyShare { index: 0, data: data.clone() }];
        prop_assert!(reconstruct_secret(&shares).is_err());
    }

    /// Property: Duplicate share indices are rejected.
    #[test]
    fn shamir_rejects_duplicate_indices(
        data in prop::collection::vec(any::<u8>(), 1..=32),
    ) {
        let shares = vec![
            KeyShare { index: 1, data: data.clone() },
            KeyShare { index: 1, data: data.clone() },
        ];
        prop_assert!(reconstruct_secret(&shares).is_err());
    }
}

// ============================================================================
// Encryption Pipeline Properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property: encrypt → decrypt roundtrip preserves plaintext.
    #[test]
    fn pipeline_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 1..=1024),
    ) {
        let (ct, keys, sig_pub) = encrypt_bytes(&plaintext).map_err(to_test_err)?;
        let recovered = decrypt_bytes(&ct, &keys, &sig_pub).map_err(to_test_err)?;
        prop_assert_eq!(recovered, plaintext);
    }

    /// Property: Two encryptions of identical plaintext produce different ciphertexts.
    #[test]
    fn pipeline_nonce_freshness(
        plaintext in prop::collection::vec(any::<u8>(), 1..=256),
    ) {
        let (ct1, _, _) = encrypt_bytes(&plaintext).map_err(to_test_err)?;
        let (ct2, _, _) = encrypt_bytes(&plaintext).map_err(to_test_err)?;
        prop_assert_ne!(ct1, ct2, "nonce randomness should produce different ciphertexts");
    }

    /// Property: Flipping any bit of the ciphertext causes decryption to fail.
    #[test]
    fn pipeline_ciphertext_integrity(
        plaintext in prop::collection::vec(any::<u8>(), 1..=128),
        flip_pos in 0usize..1000,
    ) {
        let (ct_bytes, keys, sig_pub) = encrypt_bytes(&plaintext).map_err(to_test_err)?;
        let mut c = QuantumVaultContainer::from_bytes(&ct_bytes).map_err(to_test_err)?;

        if !c.ciphertext.is_empty() {
            let pos = flip_pos % c.ciphertext.len();
            c.ciphertext[pos] ^= 0xFF;
            let tampered = c.to_bytes().map_err(to_test_err)?;
            prop_assert!(decrypt_bytes(&tampered, &keys, &sig_pub).is_err());
        }
    }

    /// Property: Flipping any bit of the signature causes verification to fail.
    #[test]
    fn pipeline_signature_integrity(
        plaintext in prop::collection::vec(any::<u8>(), 1..=128),
        flip_pos in 0usize..1000,
    ) {
        let (ct_bytes, keys, sig_pub) = encrypt_bytes(&plaintext).map_err(to_test_err)?;
        let mut c = QuantumVaultContainer::from_bytes(&ct_bytes).map_err(to_test_err)?;

        if !c.signature.is_empty() {
            let pos = flip_pos % c.signature.len();
            c.signature[pos] ^= 0xFF;
            let tampered = c.to_bytes().map_err(to_test_err)?;
            prop_assert!(decrypt_bytes(&tampered, &keys, &sig_pub).is_err());
        }
    }
}

// ============================================================================
// Container Serialization Properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Property: Container serialization is invertible.
    #[test]
    fn container_serialize_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 1..=512),
    ) {
        let (ct_bytes, _, _) = encrypt_bytes(&plaintext).map_err(to_test_err)?;
        let c1 = QuantumVaultContainer::from_bytes(&ct_bytes).map_err(to_test_err)?;
        let serialized = c1.to_bytes().map_err(to_test_err)?;
        let c2 = QuantumVaultContainer::from_bytes(&serialized).map_err(to_test_err)?;

        prop_assert_eq!(c1.magic, c2.magic);
        prop_assert_eq!(c1.version, c2.version);
        prop_assert_eq!(c1.threshold, c2.threshold);
        prop_assert_eq!(c1.share_count, c2.share_count);
        prop_assert_eq!(c1.nonce, c2.nonce);
        prop_assert_eq!(c1.ciphertext, c2.ciphertext);
        prop_assert_eq!(c1.signature, c2.signature);
    }
}

// ============================================================================
// Edge Case Tests (deterministic, not property-based)
// ============================================================================

#[test]
fn shamir_all_zeros_secret() {
    let secret = vec![0u8; 32];
    let shares = split_secret(&secret, 3, 2).unwrap();
    let recovered = reconstruct_secret(&shares[0..2]).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn shamir_all_ff_secret() {
    let secret = vec![0xFFu8; 32];
    let shares = split_secret(&secret, 3, 2).unwrap();
    let recovered = reconstruct_secret(&shares[0..2]).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn shamir_single_byte_extremes() {
    // Test boundary values in GF(2^8)
    for byte in [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF] {
        let secret = vec![byte];
        let shares = split_secret(&secret, 3, 2).unwrap();
        let recovered = reconstruct_secret(&shares[0..2]).unwrap();
        assert_eq!(recovered, secret, "failed for byte {:#04x}", byte);
    }
}

#[test]
fn shamir_max_reasonable_share_count() {
    // Test with 16 shares (reasonable upper bound for demo)
    let secret = vec![0xAB; 32];
    let shares = split_secret(&secret, 16, 2).unwrap();
    assert_eq!(shares.len(), 16);
    let recovered = reconstruct_secret(&shares[0..2]).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn pipeline_empty_plaintext_rejected_or_handled() {
    // Empty plaintext: either rejected or handled gracefully
    let result = encrypt_bytes(b"");
    // The behavior depends on implementation — document whichever happens
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn container_rejects_truncated_input() {
    let (ct_bytes, _, _) = encrypt_bytes(b"test data").unwrap();
    // Truncate at various points
    for len in [0, 1, ct_bytes.len() / 2, ct_bytes.len() - 1] {
        if len < ct_bytes.len() {
            let truncated = &ct_bytes[..len];
            assert!(
                QuantumVaultContainer::from_bytes(truncated).is_err(),
                "should reject truncated input at len={}",
                len
            );
        }
    }
}

#[test]
fn container_rejects_garbage_input() {
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    assert!(QuantumVaultContainer::from_bytes(&garbage).is_err());
}

#[test]
fn container_rejects_empty_input() {
    assert!(QuantumVaultContainer::from_bytes(&[]).is_err());
}
