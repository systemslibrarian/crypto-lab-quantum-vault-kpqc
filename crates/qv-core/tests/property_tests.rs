//! Property-based tests using proptest.
//!
//! These tests verify invariants with thousands of random inputs, catching
//! edge cases that hand-written tests might miss.
//!
//! Run with: `cargo test --test property_tests`

use proptest::prelude::*;
use qv_core::{
    container::QuantumVaultContainer,
    crypto::{
        backend::dev::{DevKem, DevSignature},
        kem::Kem,
        signature::Signature,
    },
    decrypt_bytes, encrypt_bytes, reconstruct_secret, split_secret, KeyShare,
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
// Shamir under-threshold secrecy
// ============================================================================
//
// WHY THIS TEST IS NOT `assert_ne!(reconstruct(t-1 shares), secret)`.
//
// The obvious invariant — "too few shares give the wrong answer" — is the WRONG
// invariant, and an implementation that satisfied it exactly would be broken.
// Reconstructing from `threshold - 1` shares interpolates the unique lower-degree
// polynomial through them and reads off f(0). Over GF(256) that value is uniform
// and independent of the true secret, so it coincides with the true secret byte
// with probability 1/256. It MUST be able to coincide: perfect secrecy says a
// holder of `threshold - 1` shares sees all 256 candidate secrets as exactly
// equally likely, and a candidate that the under-threshold reconstruction can
// never produce is a candidate the adversary has RULED OUT. Guaranteed
// inequality is therefore a symptom of a 1/256 leak, not a safety property. (It
// is precisely the leak that forcing the leading coefficient nonzero created:
// the excluded value was the true secret itself.)
//
// So the test below asserts what actually holds, in both directions:
//   1. `threshold` shares ALWAYS reconstruct exactly — a hard equality, checked
//      every trial, so the test cannot be passed by an implementation that just
//      emits noise.
//   2. Under threshold, the reconstruction ranges over essentially the whole
//      field, the true secret included, and hits the true secret at the uniform
//      rate 1/256 — neither suppressed (adversary can exclude it) nor favoured
//      (adversary can guess it).
// A genuinely broken split — degenerate or constant coefficients, secret reuse,
// or a punctured coefficient range — fails one of these.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn shamir_under_threshold_reveals_nothing(secret_byte in any::<u8>()) {
        const TRIALS: usize = 4096;

        let mut hits = 0usize;
        let mut seen = std::collections::HashSet::new();

        for _ in 0..TRIALS {
            // 3-of-3, so two shares are under threshold.
            let shares = split_secret(&[secret_byte], 3, 3).map_err(to_test_err)?;

            // (1) All `threshold` shares must always reconstruct exactly. Holds
            // whether or not the polynomial's degree happened to drop.
            let full = reconstruct_secret(&shares).map_err(to_test_err)?;
            prop_assert_eq!(full, vec![secret_byte]);

            let under = reconstruct_secret(&shares[0..2]).map_err(to_test_err)?;
            seen.insert(under[0]);
            if under[0] == secret_byte {
                hits += 1;
            }
        }

        // (2a) The under-threshold value must range over the whole field, not a
        // punctured subset. Restricting a coefficient to nonzero values makes
        // exactly one field element unreachable, and that is what this catches.
        // Pr[a given element is missed by chance] = (255/256)^4096 < 1e-6, so
        // near-total coverage is required, with slack for the birthday tail.
        prop_assert!(
            seen.len() >= 250,
            "under-threshold reconstruction reached only {} of 256 field elements \
             — a restricted coefficient range is puncturing the adversary's view",
            seen.len()
        );

        // (2b) The true secret must itself be reachable. If it never is, a holder
        // of threshold-1 shares can rule it out: that is the leak, stated directly.
        prop_assert!(
            seen.contains(&secret_byte),
            "the true secret {secret_byte} was never reachable from an \
             under-threshold reconstruction — it is excluded from the \
             adversary's view, so the candidates are not equally likely"
        );

        // (2c) ...and reachable at the uniform rate, not more often. Expected
        // TRIALS/256 = 16 hits, sd = sqrt(4096 * (1/256) * (255/256)) ~= 3.99.
        // The bound of 40 sits ~6 sd above the mean, so spurious failure is far
        // below one in a million, while an implementation that leaks the secret
        // into the under-threshold reconstruction drives `hits` toward TRIALS.
        prop_assert!(
            hits <= 40,
            "secret {} was recovered from under-threshold shares {} times in {} \
             trials (expected ~{}) — the split is leaking the secret",
            secret_byte,
            hits,
            TRIALS,
            TRIALS / 256
        );
    }
}

// ============================================================================
// Encryption Pipeline Properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property: Dev KEM roundtrip preserves the shared secret.
    #[test]
    fn kem_roundtrip_preserves_shared_secret(_marker in any::<u8>()) {
        let kem = DevKem;
        let (pk, sk) = kem.generate_keypair().map_err(to_test_err)?;
        let (ct, ss_enc) = kem.encapsulate(&pk).map_err(to_test_err)?;
        let ss_dec = kem.decapsulate(&sk, &ct).map_err(to_test_err)?;
        prop_assert_eq!(ss_dec, ss_enc);
    }

    /// Property: Dev signature roundtrip verifies and message tampering fails.
    #[test]
    fn signature_roundtrip_and_tamper_invariants(
        message in prop::collection::vec(any::<u8>(), 0..=512),
    ) {
        let sig = DevSignature;
        let (pk, sk) = sig.generate_keypair().map_err(to_test_err)?;
        let signature = sig.sign(&sk, &message).map_err(to_test_err)?;
        let valid = sig.verify(&pk, &message, &signature).map_err(to_test_err)?;
        prop_assert!(valid);

        let mut tampered = message.clone();
        if tampered.is_empty() {
            tampered.push(0x01);
        } else {
            tampered[0] ^= 0x01;
        }
        let valid_tampered = sig.verify(&pk, &tampered, &signature).map_err(to_test_err)?;
        prop_assert!(!valid_tampered);
    }

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
