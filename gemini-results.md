## Summary
The Quantum Vault KPQC implementation demonstrates a solid architectural foundation mapping modern Post-Quantum Cryptography (PQC) onto a threshold key-release model. Standard defenses such as parameterized bounds checking, fail-closed enum registries, and rigorous threshold matching are robust. However, several critical weaknesses compromise its adversarial boundary, notably including WASM linear memory leaks of private keys and timing oracles during the multi-share decryption loop. *(Note: The audit prompt's claim that XChaCha20-Poly1305 is utilized is entirely false; the codebase exclusively natively implements AES-256-GCM. Findings reflect the actual code truth.)*

## Critical Findings

### 1. WebAssembly Linear Memory Leakage of Input/Output Secrets
- **Location**: `crates/qv-core/src/wasm.rs` (`qv_decrypt`)
- **Issue**: The JS-to-WASM boundary interface takes `selected_pairs_json: &str` (which includes base64-encoded KEM private keys) and returns a `Vec<u8>` representing the plaintext payload. When these values cross the boundary via `wasm-bindgen`, memory is allocated within the WebAssembly linear heap. When Rust drops the memory, the system allocator simply marks the blocks as available; it does **not** zero out the underlying bytes.
- **Attack scenario**: An attacker with post-execution access to the application context (e.g., through a rogue browser extension, cross-site scripting (XSS), or a memory dump) can scan the WASM contiguous linear memory array from the Javascript side to extract the raw base64 KEM private keys and the decrypted plaintext long after the decryption function has successfully returned.
- **Severity**: Critical
- **Recommendation**: Redesign the boundary to use pre-allocated, pinned contiguous byte arrays that are shared between JS and WASM. Explicitly call `zeroize()` on those memory regions from Rust before yielding control or dropping the objects. Do not parse JSON containing key material across the boundary string-passing layer.

## High-Severity Findings

### 2. Multi-Share Decryption Early Return Timing Oracle
- **Location**: `crates/qv-core/src/decrypt.rs` (`decrypt_file`, multi-share validation loop)
- **Issue**: The decryption loop iterates over the provided `options.share_indices`. If `kem.decapsulate()` or `aead_unprotect()` fails on any single share, it immediately exits via the `?` operator.
- **Attack scenario**: An attacker provides a dynamically constructed or tampered container to a victim oracle. By observing the microsecond time delta before `DecryptionFailed` is thrown, the attacker can determine exactly *which* share index failed. A faster rejection indicates a failure on `share_indices[0]`, whereas a slower rejection implies `share_indices[0]` succeeded but `share_indices[1]` failed. This timing differential leaks whether a specific tampered KEM ciphertext produces a valid MAC against a target's private key.
- **Severity**: High
- **Recommendation**: Process all provided shares in constant time without short-circuiting. Aggregate the results into an authenticated status vector and only evaluate the overall reconstruction success threshold after all required iterations have concluded.

### 3. Stack Residue of HKDF-Derived Symmetric Keys
- **Location**: `crates/qv-core/src/encrypt.rs` (`aead_protect` and `aead_unprotect`)
- **Issue**: The symmetric share-keys and nonces are derived into static arrays (`let key = derive_share_key(ikm)?`) which do not automatically implement heap-dropped zeroization (it's a raw `[u8; 32]`). These variables go out of scope and persist as plaintext on the Rust call stack.
- **Attack scenario**: A crash, an OS core dump, or a buffer over-read vulnerability within a subsequent dependency could easily scrape the process stack and harvest the un-zeroized symmetric keys used to encrypt the core Shamir polynomials.
- **Severity**: High
- **Recommendation**: Explicitly call `key.zeroize()` immediately after seeding the key into the AES-GCM `Aes256Gcm::new` struct, or wrap the derivation outputs within a dedicated zeroizable struct to leverage `ZeroizeOnDrop` safely.

## Medium-Severity Findings

### 4. AAD Exclusion of Encrypted Shares
- **Location**: `crates/qv-core/src/encrypt.rs` (`aes_aad`)
- **Issue**: The Additional Authenticated Data (`aes_aad`) context used for the payload's final `AES-256-GCM` encryption covers metadata like `container_id`, timestamp, and algorithm IDs, but completely **omits** the `shares` array. 
- **Attack scenario**: The primary AES-GCM ciphertext tag does not cryptographically bind to the shares that encapsulate the AES file key. This delegates 100% of the payload-to-recipient binding logic to the outer HAETAE signature. If the signature check is ever stripped, conditionally skipped, or bypassed in a separate backend integration, the container becomes highly malleable—an attacker could hot-swap valid shares between different ciphertexts without invalidating the core AES authenticity tag.
- **Severity**: Medium
- **Recommendation**: Include the rigorous, serialized representation of the `shares` list in the AES-GCM `aad_bytes` context to ensure the AEAD inherently binds the ciphertext to its exact encapsulation vector.

### 5. Ineffective `catch_unwind` Over C FFI Blocks
- **Location**: `crates/qv-core/src/crypto/backend/kpqc_ffi.rs` 
- **Issue**: The codebase wraps `unsafe {}` C FFI invocations (like the SMAUG and HAETAE C code) inside `std::panic::catch_unwind`.
- **Attack scenario**: `catch_unwind` ONLY intercepts native Rust panics. If a maliciously crafted header causes the underlying untrusted C library to abort, segfault, execute an illegal instruction, or trigger memory corruption, the entire OS process will immediately crash. `catch_unwind` gives a radically false sense of failure isolation.
- **Severity**: Medium
- **Recommendation**: Remove `catch_unwind` as it obscures the real impact profile of C interop. To achieve genuine panic resistance for potentially unstable C-reference binaries, compile them to WebAssembly and sandbox them via an engine like `Wasmtime` or execute them in isolated sub-processes.

## Low-Severity / Informational

### 6. Misaligned Component Assertion: "XChaCha20-Poly1305"
- **Location**: `crates/qv-core/src/encrypt.rs` and `Cargo.toml`
- **Issue**: The auditing prompt explicitly scoped the review to an assumption that the project uses `XChaCha20-Poly1305`. A codebase search and logical inspection prove this is false; the payload and wrapping operations unconditionally use `AES-256-GCM`.
- **Severity**: Informational
- **Recommendation**: Ensure external security assumptions and architectural specifications match the committed source code truth.

### 7. Non-Secret Dependent Rejection Sampling Timing
- **Location**: `crates/qv-core/src/shamir.rs` (`split_secret`)
- **Issue**: The rejection sampling loop `while v == 0 { v = rng.next_u32() as u8; }` creates a minuscule timing divergence based on the CSPRNG's output pipeline.
- **Severity**: Low
- **Recommendation**: Because the value controls random GF(256) coefficients rather than the original secret, it practically does not expose user data. However, to maintain strict constant-time cryptographic practices universally, implement a masking or constant-time modulus pattern for random coordinate formulation.

## Testing Gaps
- **Cross-Version & Downgrade Path Rejection**: No coverage exists proving that when `CONTAINER_VERSION: 3` is introduced, older parsers fail safely, nor is there a test proving that a fabricated `version: 1` structure is deterministically aborted by the `v2` parser.
- **Share Injection Coverage**: Validation ignores the specific edge case of "Valid Outer Shell / Swapped Internal Shares." There is no test covering what happens if valid shares from a separate container are injected to verify the HAETAE failure threshold.
- **FFI Boundary Panics**: Fuzzing focuses heavily on Rust structs, yet there is sparse panic-resistance logic to confirm what happens when C bindings are intentionally over-saturated with bad lengths right at the `std::slice::from_raw_parts` line of `kpqc_ffi.rs`.

## Documentation Gaps
- **Attacker Model Assumptions**: No unique document outlines the assumed threat conditions. Specifically, the repository fails to codify if the runtime (e.g., the browser environment hosting the WASM) is considered hostile or trusted.
- **Strict Format Serializer Semantics**: While `container.rs` defines serde mappings natively, there is no language-agnostic layout specification codifying the strict base64 assumptions, field order, and exact serialization canonicalization steps to recreate `container_signing_bytes` securely in Go, C++, or TypeScript.
- **Logging Policy**: Missing an explicit written protocol mandating that decryption errors, algorithm mismatches, and `Debug` implementations of wrapper boundaries never bleed context bounds to terminal logging (vital given early exits).

## Positive Observations
- **Fail-Closed Deserialization**: The explicit parameterized length restrictions and enum-matching approach via `serde(deny_unknown_fields)` are extremely protective against deserialization exhaustion vectors.
- **Memory Safety Lifecycle**: Phenomenal pervasive adoption of the `ZeroizeOnDrop` macro on intermediate structures (e.g., `DecryptOptions` and Shamir `Share`), ensuring high-level structs do effectively attempt scope cleaning.
- **Correct Usage of HKDF Domain Specs**: `derive_labeled_bytes` utilizes proper HKDF extraction semantics, securely leveraging explicit domain separation labels `HKDF_LABEL_SHARE_KEY` and `HKDF_LABEL_SHARE_NONCE` mitigating cross-context symmetric key contamination.