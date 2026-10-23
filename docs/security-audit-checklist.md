# Quantum Vault — Cryptographic Security Audit Checklist

**Version:** 1.1
**Based on:** Security audit commit 4f3cde6 plus the 2026-10-23 evidence review
**Last reviewed:** 2026-10-23

Use this checklist when reviewing the implementation for security regressions,
auditing a new backend, or accepting pull requests that touch cryptographic code.

---

## 1. Randomness Sources

- [ ] **R-001** All key generation uses an OS-backed CSPRNG (`OsRng`, native OS entropy, or browser `crypto.getRandomValues`).
- [ ] **R-002** The file key $K$ is generated with `OsRng.fill_bytes()`, not seeded from user input.
- [ ] **R-003** Nonce construction matches the reviewed path: Rust derives the outer nonce with HKDF from a fresh random 16-byte `container_id`; the browser samples its 12-byte outer nonce with Web Crypto. Neither path hardcodes or reuses a nonce/key pair.
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
- [ ] **R-005** The Rust `wasm32` target enables `getrandom`'s `js` feature. The active C-derived browser artifacts use their recorded JavaScript/getentropy shims; verify the artifact-specific reproduction rather than assuming the Rust feature config applies to them.
- [ ] **R-006** The conditional native C backend's `randombytes_shim.c` uses `getrandom(2)`, `arc4random_buf(3)`, or fail-closed `/dev/urandom` reads—never `rand()`. It is not the Rust `dev-backend`.

---

## 2. Memory Zeroization

- [ ] **Z-001** The file key `K` is zeroized immediately after Shamir splitting (`file_key.zeroize()`).
- [ ] **Z-002** KEM shared secrets (`ss`) are zeroized after each share is AEAD-protected or an error is returned.
- [ ] **Z-003** Reconstructed file key is zeroized after AES decryption.
- [ ] **Z-004** Recovered Shamir share data is zeroized after reconstruction.
- [ ] **Z-005** `Share` type implements `ZeroizeOnDrop`.
- [ ] **Z-006** `EncryptOptions.signer_private_key` is covered by the redacted `Debug` impl (no accidental logging).
- [ ] **Z-007** Polynomial coefficients in `split_secret` are zeroized after each byte's evaluation.
- [ ] **Z-008** The browser Shamir path keeps coefficients in one typed buffer cleared on every exit and does not create ordinary JavaScript arrays containing secret/share bytes during interpolation.

---

## 3. Signature Verification Order

- [ ] **S-001** Container signature is verified **before** any KEM decapsulation.
- [ ] **S-002** Container signature is verified **before** AES-GCM decryption.
- [ ] **S-003** Signature failure causes an immediate error return; no partial plaintext is returned.
- [ ] **S-004** The Rust signing corpus covers every Rust container field except `signature`. The browser corpus covers every `SealedBox` cryptographic field, but not the outer `.qvault` version, algorithm object or labels; import validates those against fixed expected values.
- [ ] **S-005** `DevSignature.verify` uses `subtle::ConstantTimeEq` to compare MACs.
- [ ] **S-006** Treat `DevSignature` as a publicly forgeable test checksum, not a signature: `SHA-256(SHA-256(privkey) || message)` equals `SHA-256(pubkey || message)`, so anyone with the public verification key can sign. The module and convenience APIs must be absent without `dev-backend`, and unacknowledged release builds with that feature must fail.

---

## 4. Authenticated Encryption (AES-256-GCM)

- [ ] **A-001** Rust outer AAD covers all nine fields: `cipher`, `container_id`, `created_at`, `kem_algorithm`, `nonce`, `share_count`, `sig_algorithm`, `threshold`, and `version`.
- [ ] **A-002** The nonce is 12 bytes (96 bits) as required by GCM.
- [ ] **A-003** Rust outer AES decryption uses the exact recomputed `Payload { msg, aad }`. Per-share Rust and browser AES operations deliberately use empty AAD on both encryption and decryption and rely on their enclosing signed context for field binding.
- [ ] **A-004** The container stores the GCM-auth-tag-appended ciphertext (output of `aes_gcm::Aead::encrypt`).
- [ ] **A-005** AES decryption failure returns `Err` — the error message does not reveal the key or plaintext.
- [ ] **A-006** AAD JSON keys are sorted alphabetically to ensure deterministic byte-for-byte match.

---

## 5. Container Parsing Safety

- [ ] **P-001** Rust serialized input is checked against the 8 MiB `MAX_CONTAINER_BYTES` cap before JSON parsing; its ciphertext is separately capped at 4 MiB.
- [ ] **P-002** `magic` field is verified to equal `"QVKP"` and version is 2.
- [ ] **P-003** `version` field is verified to equal the supported version.
- [ ] **P-004** `threshold >= 2` is enforced.
- [ ] **P-005** `share_count >= threshold` is enforced.
- [ ] **P-006** `shares.len() == share_count` is enforced (prevents index-out-of-bounds in the decrypt path).
- [ ] **P-007** `nonce.len() == 12` is enforced before AES use.
- [ ] **P-008** Share indices are 1-based and unique (no duplicate `index` values in `shares`).
- [ ] **P-009** Container algorithm identifiers must match the selected KEM and signature backends before either backend processes the container.
- [ ] **P-010** Before signature verification, code performs only structural/policy validation and checks declared algorithm IDs against the selected backends. No KEM decapsulation or AES processing uses payload fields until the signature succeeds.

---

## 6. Shamir Secret Sharing (GF(2⁸))

- [ ] **H-001** Share index 0 is rejected by `reconstruct_secret` (index 0 = secret polynomial constant term).
- [ ] **H-002** Duplicate share indices are rejected by `reconstruct_secret`.
- [ ] **H-003** Inconsistent payload lengths across shares are rejected.
- [ ] **H-004** An empty share list is rejected.
- [ ] **H-005** Decryption uses `share_indices` to match private keys to shares by position, not by array order.
- [ ] **H-006** Reconstruction with fewer than `threshold` shares produces an unauthenticated candidate, not an error. That candidate can equal the secret by chance; callers enforce the threshold and must not infer success from inequality/equality alone.

---

## 7. Key Encapsulation Mechanism (FFI Safety)

- [ ] **K-001** `smaug_t_keypair`, `smaug_t_enc`, `smaug_t_dec` initialise output buffers to zero before calling C.
- [ ] **K-002** `haetae_keypair` and `haetae_sign` initialize output buffers to zero before calling C. `haetae_verify` has no output buffer; it validates public-key and signature lengths before the call.
- [ ] **K-003** `haetae_sign` uses a `usize` `siglen` out-parameter, matching C `size_t` for the target ABI (not `u32`), and rejects a returned length above the allocated maximum.
- [ ] **K-004** `haetae_verify` passes all 7 required arguments in the correct order.
- [ ] **K-005** C symbols use the upstream `cryptolab_smaug3_crypto_kem_*` / `cryptolab_haetae_mode3_*` namespaces and the SMAUG-T keypair declaration matches its void return type.
- [ ] **K-006** Buffer sizes in `kpqc_ffi.rs` match the constants in the C header (`pk`, `sk`, `ct`, `ss`, `sig`).
- [ ] **K-007** `build.rs` excludes each vendor `randombytes.c` and compiles `randombytes_shim.c` instead.
- [ ] **K-008** `kpqc-native` feature guard prevents FFI code from being compiled in default / WASM builds.
- [ ] **K-009** (Pre-production) FFI boundary inputs are fuzz-tested with malformed data to catch C-side crashes. Note: `catch_unwind` cannot intercept C-level crashes (segfault, abort); consider WASM sandboxing or subprocess isolation for hostile inputs.

---

## 8. Build and Compilation Guards

- [ ] **B-001** `compile_error!` prevents `dev-backend` from being active in a release build unless the separate `allow_dev_backend_in_release` acknowledgement feature is also active.
- [ ] **B-002** Non-development builds use `--no-default-features` plus an implemented, reviewed backend; the default feature set is development-only and `kpqc-wasm` is currently an error-only scaffold, not evidence of working KpqC crypto.
- [ ] **B-003** `build.rs` defines `SMAUG_MODE=3` and `HAETAE_CONFIG_MODE=HAETAE_MODE3`; the claim is parameter selection, not KAT evidence.
- [ ] **B-004** `build.rs` compiles the reviewed SMAUG-T library files explicitly, excluding both `randombytes.c` and the OpenSSL/KAT-oriented `rng.c`; HAETAE compilation is confined to its pinned `reference_implementation/src` directory and excludes `randombytes.c`; test/KAT directories are not compiled.
- [ ] **B-005** `allow_dev_backend_in_release` feature exists as an explicit opt-in escape hatch.
- [ ] **B-006** Algorithm-registry membership is not treated as a production-safety attestation; `is_production_safe()` fails closed for every current entry.

---

## 9. Constant-Time Operations

- [ ] **CT-001** `DevSignature.verify` compares MACs with `ConstantTimeEq`, not `==`.
- [ ] **CT-002** Share index comparison in `decrypt.rs` uses iterator finds, not secret-dependent branches on key bytes.
- [ ] **CT-003** Rust AES-256-GCM authentication uses the `aes-gcm` crate's verification path, not a bespoke `==`; review the exact dependency and target implementation before making a whole-platform constant-time claim.
- [ ] **CT-004** Each Rust Shamir share is protected by `aead_protect` (AES-256-GCM) and uses the same library authentication path; the browser uses Web Crypto and requires separate platform analysis.

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
| C-001 | CRITICAL | DevSignature was described as a secure signature | Contained, not cryptographically fixed: the current checksum is forgeable from its public key and is restricted to explicitly enabled development builds |
| H-005 | HIGH | Decrypt matched shares by array position, not by index | Fixed: index-based lookup |
| M-001 | MEDIUM | AES AAD was empty | Fixed: Rust outer AAD covers the nine documented context fields |
| M-002 | MEDIUM | No container size limit | Fixed: 8 MiB serialized / 4 MiB ciphertext caps in Rust |
| M-003 | MEDIUM | No structural validation in from_bytes | Fixed: strict schema, identifiers, policy, lengths and per-share bounds |
| L-002 | LOW | dev-backend could ship in release | Fixed: feature-gated module/API plus compile-time release guard, with an explicit fuzz/benchmark escape hatch |
| … | … | … (20 total) | Re-evaluate individually; this historical summary is not evidence that every finding remains resolved |
