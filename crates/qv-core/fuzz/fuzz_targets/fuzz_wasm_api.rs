//! Fuzz target: exercise the native-callable WASM API boundary.
//!
//! This harness focuses on the *successful* native execution path of the
//! wasm-bindgen exports. Error-path fuzzing is limited on non-wasm targets
//! because `JsError::new` is a JS import and may panic outside a real WASM
//! runtime. Even so, this target still covers a high-risk surface:
//!
//!   1. JSON/base64 encoding and decoding across the exported API.
//!   2. Container serialization and parsing through `qv_encrypt` / `qv_decrypt`.
//!   3. Share index selection and threshold decryption wiring.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_wasm_api

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use qv_core::wasm::{qv_decrypt, qv_encrypt, qv_kem_generate_keypair, qv_sig_generate_keypair};

#[derive(Arbitrary, Debug)]
struct Input {
    plaintext: Vec<u8>,
    reverse_share_order: bool,
}

fuzz_target!(|input: Input| {
    let Ok(kem1_json) = qv_kem_generate_keypair() else { return };
    let Ok(kem2_json) = qv_kem_generate_keypair() else { return };
    let Ok(sig_json) = qv_sig_generate_keypair() else { return };

    let Ok(kem1): Result<serde_json::Value, _> = serde_json::from_str(&kem1_json) else { return };
    let Ok(kem2): Result<serde_json::Value, _> = serde_json::from_str(&kem2_json) else { return };
    let Ok(sig): Result<serde_json::Value, _> = serde_json::from_str(&sig_json) else { return };

    let Some(kem1_pub) = kem1["pub"].as_str() else { return };
    let Some(kem1_priv) = kem1["priv"].as_str() else { return };
    let Some(kem2_pub) = kem2["pub"].as_str() else { return };
    let Some(kem2_priv) = kem2["priv"].as_str() else { return };
    let Some(sig_pub) = sig["pub"].as_str() else { return };
    let Some(sig_priv) = sig["priv"].as_str() else { return };

    let pubkeys_json = serde_json::json!([kem1_pub, kem2_pub]).to_string();
    let Ok(container_json) = qv_encrypt(&input.plaintext, &pubkeys_json, 2, sig_priv) else { return };

    let Ok(container): Result<serde_json::Value, _> = serde_json::from_str(&container_json) else { return };
    let Some(idx1) = container["shares"][0]["index"].as_u64() else { return };
    let Some(idx2) = container["shares"][1]["index"].as_u64() else { return };

    let selected_pairs = if input.reverse_share_order {
        serde_json::json!([
            { "shareIndex": idx2 as u8, "privKey": kem2_priv },
            { "shareIndex": idx1 as u8, "privKey": kem1_priv }
        ])
    } else {
        serde_json::json!([
            { "shareIndex": idx1 as u8, "privKey": kem1_priv },
            { "shareIndex": idx2 as u8, "privKey": kem2_priv }
        ])
    }
    .to_string();

    let Ok(recovered) = qv_decrypt(&container_json, &selected_pairs, sig_pub) else { return };
    assert_eq!(recovered, input.plaintext, "WASM API roundtrip must preserve plaintext");
});