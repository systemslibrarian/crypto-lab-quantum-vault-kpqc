//! Fuzz target: exercise signature verification on malformed inputs.
//!
//! Properties under test:
//!   1. `verify` must never panic on malformed `(pubkey, message, signature)` triples.
//!   2. For a valid generated keypair and message, `verify(pk, msg, sign(sk, msg))` is true.
//!   3. Mutating the signature, message, or public key must never crash the verifier.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_signature_verify

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use qv_core::crypto::{backend::dev::DevSignature, signature::Signature};

#[derive(Arbitrary, Debug)]
struct Input {
    message: Vec<u8>,
    malformed_pubkey: Vec<u8>,
    malformed_signature: Vec<u8>,
    flip_signature_bit: bool,
    flip_message_bit: bool,
    flip_pubkey_bit: bool,
}

fuzz_target!(|input: Input| {
    let sig = DevSignature;

    let _ = sig.verify(&input.malformed_pubkey, &input.message, &input.malformed_signature);

    let Ok((pubkey, privkey)) = sig.generate_keypair() else { return };
    let Ok(mut signature) = sig.sign(&privkey, &input.message) else { return };

    assert!(
        sig.verify(&pubkey, &input.message, &signature).unwrap_or(false),
        "valid signature must verify"
    );

    let mut tampered_message = input.message.clone();
    let mut tampered_pubkey = pubkey.clone();

    if input.flip_signature_bit && !signature.is_empty() {
        signature[0] ^= 0x01;
    }
    if input.flip_message_bit && !tampered_message.is_empty() {
        tampered_message[0] ^= 0x01;
    }
    if input.flip_pubkey_bit && !tampered_pubkey.is_empty() {
        tampered_pubkey[0] ^= 0x01;
    }

    let _ = sig.verify(&tampered_pubkey, &tampered_message, &signature);
});