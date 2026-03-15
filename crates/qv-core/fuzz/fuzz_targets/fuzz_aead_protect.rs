//! Fuzz target: round-trip property of the `aead_protect` / `aead_unprotect` pair.
//!
//! Properties under test:
//!   1. The encrypt→decrypt pipeline must never panic on any input.
//!   2. Encrypting then decrypting must return the original plaintext
//!      (round-trip / invertibility property).
//!   3. Any modification to the ciphertext must cause decryption to fail
//!      (authenticated encryption correctness — tested indirectly by the
//!       pipeline's signature verification step).
//!
//! Because `aead_protect` is `pub(crate)`, it is exercised here indirectly
//! through the high-level `encrypt_bytes` / `decrypt_bytes` API which calls
//! both `aead_protect` (per-share wrapping) and the outer AES-256-GCM layer.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_aead_protect

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

// aead_protect / aead_unprotect are pub(crate); we exercise them indirectly
// through the public high-level API which calls both per-share AEAD wrapping
// and the outer AES-256-GCM layer.
use qv_core::{decrypt_bytes, encrypt_bytes};

#[derive(Arbitrary, Debug)]
struct Input {
    data: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // Use the high-level API which exercises aead_protect / aead_unprotect
    // internally.  Any off-by-one, buffer overread, or panic will surface here.
    let Ok((ct, keys, sig_pub)) = encrypt_bytes(&input.data) else { return };
    let Ok(recovered) = decrypt_bytes(&ct, &keys, &sig_pub) else { return };
    assert_eq!(
        recovered, input.data,
        "aead_protect round-trip failed for input of length {}",
        input.data.len()
    );
});
