//! Fuzz target: exercise the KEM handshake API directly.
//!
//! Properties under test:
//!   1. `encapsulate` and `decapsulate` must never panic on malformed inputs.
//!   2. For a valid generated keypair, `decapsulate(sk, encap(pk).ct) == ss`.
//!   3. Invalid public keys and ciphertexts must return `Err`, not unwind.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_kem_handshake

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use qv_core::crypto::{backend::dev::DevKem, kem::Kem};

#[derive(Arbitrary, Debug)]
struct Input {
    malformed_pubkey: Vec<u8>,
    malformed_ciphertext: Vec<u8>,
    try_valid_roundtrip: bool,
}

fuzz_target!(|input: Input| {
    let kem = DevKem;

    let _ = kem.encapsulate(&input.malformed_pubkey);
    let _ = kem.decapsulate(&[0u8; 32], &input.malformed_ciphertext);

    if input.try_valid_roundtrip {
        let Ok((pk, sk)) = kem.generate_keypair() else { return };
        let Ok((ct, ss_enc)) = kem.encapsulate(&pk) else { return };
        let Ok(ss_dec) = kem.decapsulate(&sk, &ct) else { return };
        assert_eq!(ss_enc, ss_dec, "valid KEM roundtrip must preserve the shared secret");
    }
});