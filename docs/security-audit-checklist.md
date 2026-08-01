# Quantum Vault — Cryptographic Security Audit Checklist

**Version:** 1.0  
**Based on:** Security audit commit 4f3cde6 (all 20 findings resolved)  
**Last reviewed:** 2026-03

Use this checklist when reviewing the implementation for security regressions,
auditing a new backend, or accepting pull requests that touch cryptographic code.

---

## 1. Randomness Sources

- [ ] **R-001** All key generation uses a CSPRNG (`rand::thread_rng()` or OS-level).
- [ ] **R-002** The file key $K$ is generated with `rng.fill_bytes()`, not seeded from user input.
- [ ] **R-003** The AES-GCM nonce is generated with `rng.fill_bytes()` — never hardcoded or derived.
- [ ] **R-004** **Every** Shamir polynomial coefficient above the constant term — the **leading**
      coefficient `a_{threshold-1}` included — is drawn uniformly over the full field, 0 included
      (a single `rng.fill_bytes(&mut coeffs[1..])`, no rejection loop, no `0 -> 1` map). The
      TypeScript demo must match, byte for byte.

      *Why the leading coefficient is not an exception.* Fix any `threshold - 1` shares. For each
      candidate secret `S` there is exactly one coefficient vector that hits those shares and has
      `f(0) = S`, and that vector's leading coefficient is an affine, non-degenerate function of
      `S`. So barring the leading coefficient from being 0 makes exactly one candidate secret
      unreachable: the adversary can *rule it out*, and the 256 candidates are no longer equally
      likely. That is a 1/256-per-byte leak in exactly the property the docs claim
      ("reveals zero information", "perfect secrecy", "information-theoretically secure",
      "a single share reveals NOTHING"). At the shipped 2-of-3 setting the sole non-constant
      coefficient *is* the leading one, so the constraint applied to every byte of every real key —
      restricting only the non-leading coefficients would be a no-op there.

      *Why the resulting degree drop is harmless.* A zero leading coefficient (probability 1/256)
      makes the polynomial degree less than `threshold - 1`. It does **not** let `threshold - 1`
      shares reconstruct in any meaningful sense: interpolating `threshold - 1` shares yields the
      true secret exactly when the degree dropped, which is probability 1/256 — the same as
      guessing — and the shareholders cannot tell the degenerate case from the full-degree one,
      since the two views are identically distributed. Correctness is likewise unaffected: any
      `threshold` points determine a unique polynomial of degree at most `threshold - 1`, so
      Lagrange interpolation at `x = 0` still returns the secret.

      *Regression trap.* A test asserting `reconstruct(threshold - 1 shares) != secret` will now
      fail about 1/256 of the time per byte, and that flakiness is correct behaviour, not a bug.
      Do not "fix" it by reintroducing the nonzero constraint. See
      `shamir_under_threshold_reveals_nothing` in `crates/qv-core/tests/property_tests.rs` for the
      invariant that actually holds.
- [ ] **R-005** WASM / browser builds use `getrandom` with `features = ["js"]` to reach `crypto.getRandomValues`.
- [ ] **R-006** The dev backend (`randombytes_shim.c`) uses `getrandom(2)` / `arc4random_buf(3)`, never `rand()`.

---

## 2. Memory Zeroization

- [ ] **Z-001** The file key `K` is zeroized immediately after Shamir splitting (`file_key.zeroize()`).
- [ ] **Z-002** KEM shared secrets (`ss`) are zeroized after each share is AEAD-protected.
- [ ] **Z-003** Reconstructed file key is zeroized after AES decryption.
- [ ] **Z-004** Recovered Shamir share data is zeroized after reconstruction.
- [ ] **Z-005** `Share` type implements `ZeroizeOnDrop`.
- [ ] **Z-006** `EncryptOptions.signer_private_key` is covered by the redacted `Debug` impl (no accidental logging).
- [ ] **Z-007** Polynomial coefficients in `split_secret` are zeroized after each byte's evaluation.

---

## 3. Signature Verification Order

- [ ] **S-001** Container signature is verified **before** any KEM decapsulation.
- [ ] **S-002** Container signature is verified **before** AES-GCM decryption.
- [ ] **S-003** Signature failure causes an immediate error return; no partial plaintext is returned.
- [ ] **S-004** The signing canonical byte string covers ALL fields except `signature` itself.
- [ ] **S-005** `DevSignature.verify` uses `subtle::ConstantTimeEq` to compare MACs.
- [ ] **S-006** `DevSignature.sign` computes `SHA-256(SHA-256(privkey) || message)` — the signing key SHA256 prevents length-extension and ensures only the key holder can sign.

---

## 4. Authenticated Encryption (AES-256-GCM)

- [ ] **A-001** AAD covers `version`, `threshold`, `kem_algorithm`, `sig_algorithm` — no downgrade possible.
- [ ] **A-002** The nonce is 12 bytes (96 bits) as required by GCM.
- [ ] **A-003** AES decryption uses `Payload { msg, aad }` — the AAD is always provided, never empty unless the same AAD was used during encryption.
- [ ] **A-004** The container stores the GCM-auth-tag-appended ciphertext (output of `aes_gcm::Aead::encrypt`).
- [ ] **A-005** AES decryption failure returns `Err` — the error message does not reveal the key or plaintext.
- [ ] **A-006** AAD JSON keys are sorted alphabetically to ensure deterministic byte-for-byte match.

---

## 5. Container Parsing Safety

- [ ] **P-001** Input length is checked against a 64 MiB cap before JSON parsing.
- [ ] **P-002** `magic` field is verified to equal `"QVLT1"`.
- [ ] **P-003** `version` field is verified to equal the supported version.
- [ ] **P-004** `threshold >= 2` is enforced.
- [ ] **P-005** `share_count >= threshold` is enforced.
- [ ] **P-006** `shares.len() == share_count` is enforced (prevents index-out-of-bounds in the decrypt path).
- [ ] **P-007** `nonce.len() == 12` is enforced before AES use.
- [ ] **P-008** Share indices are 1-based and unique (no duplicate `index` values in `shares`).
- [ ] **P-009** No container field is trusted for cryptographic decisions before signature verification.

---

## 6. Shamir Secret Sharing (GF(2⁸))

- [ ] **H-001** Share index 0 is rejected by `reconstruct_secret` (index 0 = secret polynomial constant term).
- [ ] **H-002** Duplicate share indices are rejected by `reconstruct_secret`.
- [ ] **H-003** Inconsistent payload lengths across shares are rejected.
- [ ] **H-004** An empty share list is rejected.
- [ ] **H-005** Decryption uses `share_indices` to match private keys to shares by position, not by array order.
- [ ] **H-006** Reconstruction with fewer than `threshold` shares produces garbage, not an error — callers must validate share count before calling.

---

## 7. Key Encapsulation Mechanism (FFI Safety)

- [ ] **K-001** `smaug_t_keypair`, `smaug_t_enc`, `smaug_t_dec` initialise output buffers to zero before calling C.
- [ ] **K-002** `haetae_keypair`, `haetae_sign`, `haetae_verify` initialise output buffers to zero before calling C.
- [ ] **K-003** `haetae_sign` uses a correctly sized `siglen: libc::size_t` out-parameter (not `u32`).
- [ ] **K-004** `haetae_verify` passes all 7 required arguments in the correct order.
- [ ] **K-005** C symbols use the correct `cryptolab_smaugt_mode3_*` / `cryptolab_haetae_mode3_*` prefix.
- [ ] **K-006** Buffer sizes in `kpqc_ffi.rs` match the constants in the C header (`pk`, `sk`, `ct`, `ss`, `sig`).
- [ ] **K-007** `randombytes_shim.c` excludes the NIST DRBG `rng.c` from the build (linker flag in `build.rs`).
- [ ] **K-008** `kpqc-native` feature guard prevents FFI code from being compiled in default / WASM builds.
- [ ] **K-009** (Pre-production) FFI boundary inputs are fuzz-tested with malformed data to catch C-side crashes. Note: `catch_unwind` cannot intercept C-level crashes (segfault, abort); consider WASM sandboxing or subprocess isolation for hostile inputs.

---

## 8. Build and Compilation Guards

- [ ] **B-001** `compile_error!` prevents `dev-backend` from being active in release builds.
- [ ] **B-002** `dev-backend` is **not** in the `default` features of any production profile.
- [ ] **B-003** `build.rs` defines `SMAUGT_MODE=3` and `HAETAE_MODE=3` to match the KAT test vectors.
- [ ] **B-004** `build.rs` excludes C test/KAT files from the native build.
- [ ] **B-005** `allow_dev_backend_in_release` feature exists as an explicit opt-in escape hatch.

---

## 9. Constant-Time Operations

- [ ] **CT-001** `DevSignature.verify` compares MACs with `ConstantTimeEq`, not `==`.
- [ ] **CT-002** Share index comparison in `decrypt.rs` uses iterator finds, not secret-dependent branches on key bytes.
- [ ] **CT-003** AES-256-GCM authentication tag comparison is performed by the `aes-gcm` crate internals (constant-time).
- [ ] **CT-004** Each Shamir share is protected by `aead_protect` (AES-256-GCM); authentication tag verification is performed by the `aes-gcm` crate internals (constant-time).

---

## 10. Debug / Logging Safety

- [ ] **L-001** `EncryptOptions` has a `Debug` impl that redacts `signer_private_key`.
- [ ] **L-002** `DecryptOptions` has a `Debug` impl that redacts `recipient_private_keys`.
- [ ] **L-003** No `println!` / `dbg!` / `log::debug!` calls output key material in the `crypto/` subtree.
- [ ] **L-004** Error messages from AES decryption do not include plaintext or key bytes.

---

## Checklist Usage

When opening a PR that touches cryptographic code, complete the relevant
sections of this checklist in the PR description. Mark each item as:

- ✅ Satisfied (with brief note)
- ⚠️ Not applicable (with reason)
- ❌ Not satisfied (must be resolved before merge)

For a full security audit, all items must be ✅ or ⚠️.

---

## Previous Audit Summary

Audit conducted 2025-XX, findings committed in `4f3cde6`:

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| C-001 | CRITICAL | DevSignature used SHA-256(privkey \|\| msg) — malleable | Fixed: now SHA-256(SHA-256(pk) \|\| msg) |
| H-005 | HIGH | Decrypt matched shares by array position, not by index | Fixed: index-based lookup |
| M-001 | MEDIUM | AES AAD was empty | Fixed: covers version/threshold/algorithms |
| M-002 | MEDIUM | No container size limit | Fixed: 64 MiB cap |
| M-003 | MEDIUM | No structural validation in from_bytes | Fixed: 6 checks added |
| L-002 | LOW | dev-backend could ship in release | Fixed: compile_error! guard |
| … | … | … (20 total) | All resolved |
