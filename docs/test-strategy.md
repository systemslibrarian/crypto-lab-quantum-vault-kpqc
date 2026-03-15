# Test Strategy

This document describes the testing approach for the Quantum Vault – KPQC project.

## Test Inventory

| Layer | Location | Count | Notes |
|-------|----------|-------|-------|
| **Rust Unit/Integration** | `crates/qv-core/tests/test_vectors.rs` | 14 | NIST vectors, Shamir deterministic tests, pipeline roundtrips |
| **Rust Property Tests** | `crates/qv-core/tests/property_tests.rs` | 21 | proptest-based fuzzing, Shamir & pipeline invariants |
| **Rust Fuzz Targets** | `crates/qv-core/fuzz/fuzz_targets/*.rs` | 5 | libfuzzer-based crash testing |
| **TypeScript Unit Tests** | `web-demo/src/**/__tests__/*.test.ts` | 61 | Shamir, AES-GCM, pipeline integration, .qvault file export/import |
| **Doc Tests** | `crates/qv-core/src/lib.rs` | 1 | Example code verification |

**Total: 102+ tests**

## Property-Based Tests (proptest)

Property tests verify invariants over randomly generated inputs:

### Shamir Properties
- **Roundtrip completeness**: `split_secret(s) → reconstruct_secret() == s`
- **Threshold sufficiency**: Any `t` shares suffice for reconstruction
- **Under-threshold failure**: `t-1` shares produce incorrect output
- **Order independence**: Share order doesn't affect reconstruction
- **Share length invariant**: `share.data.len() == secret.len()`
- **Index uniqueness**: All share indices are unique and 1-based
- **Zero-index rejection**: Shares with index=0 are rejected
- **Duplicate index rejection**: Duplicate share indices are rejected

### Pipeline Properties
- **Encrypt/decrypt roundtrip**: `decrypt(encrypt(pt)) == pt`
- **Nonce freshness**: Two encryptions of same plaintext differ
- **Ciphertext integrity**: Bit-flip in ciphertext → decryption fails
- **Signature integrity**: Bit-flip in signature → verification fails

### Container Properties
- **Serialization roundtrip**: `from_bytes(to_bytes(c)) == c`

## Fuzz Targets

Located in `crates/qv-core/fuzz/fuzz_targets/`:

| Target | Purpose | Coverage |
|--------|---------|----------|
| `fuzz_aead_protect` | AEAD encryption edge cases | Nonce handling, key sizes |
| `fuzz_container_parse` | Container deserialization | Malformed JSON, truncation |
| `fuzz_decrypt_pipeline` | Full decryption path | Invalid keys, tampered data |
| `fuzz_shamir_reconstruct` | Share reconstruction | Invalid indices, lengths |
| `fuzz_shamir_roundtrip` | Split/reconstruct cycle | All parameter combinations |

### Running Fuzzing

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run a specific target
cargo +nightly fuzz run fuzz_shamir_roundtrip -- -max_total_time=60

# Run all targets sequentially
for target in fuzz_aead_protect fuzz_container_parse fuzz_decrypt_pipeline fuzz_shamir_reconstruct fuzz_shamir_roundtrip; do
    cargo +nightly fuzz run "$target" -- -max_total_time=30
done
```

## CI Pipeline

The `.github/workflows/ci.yml` workflow runs on every push/PR:

1. **Build**: `cargo build --workspace`
2. **Test**: `cargo test --workspace` (includes property tests)
3. **WASM**: `cargo test -p qv-core --features wasm`
4. **Lint**: `cargo clippy --workspace`
5. **Format**: `cargo fmt --all -- --check`
6. **Audit**: `cargo audit` (dependency vulnerability check)
7. **Web tests**: `npm run test` (Vitest for TypeScript)
8. **Web lint**: `npm run lint` (ESLint)
9. **Build web**: `npm run build` (type-check + vite build)

Fuzz testing runs on a separate schedule in `.github/workflows/fuzz.yml`.

## Coverage Gaps & Future Work

| Gap | Priority | Status |
|-----|----------|--------|
| Mutation testing (cargo-mutants) | LOW | Future |
| Cross-implementation test vectors | MEDIUM | Partially done (TS ↔ Rust) |
| Browser integration tests (Playwright) | LOW | Future |
| Memory leak detection (miri) | HIGH | Requires nightly |

## Running Tests Locally

```bash
# Rust tests only
cargo test --workspace

# Rust property tests (verbose)
cargo test --test property_tests -- --nocapture

# TypeScript tests
cd web-demo && npm run test

# All tests
cargo test --workspace && cd web-demo && npm run test
```

## Test Vector Sources

- **AES-256-GCM**: [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- **Shamir SSS**: Custom deterministic vectors with fixed RNG seed
- **ML-KEM / ML-DSA**: N/A (demo uses CRYSTALS stubs, not NIST vectors)

## Adding New Tests

### Property Test
Add to `crates/qv-core/tests/property_tests.rs`:

```rust
proptest! {
    #[test]
    fn my_new_property(input in strategy) {
        let result = function_under_test(&input).map_err(to_test_err)?;
        prop_assert!(invariant(result));
    }
}
```

### Fuzz Target
Create `crates/qv-core/fuzz/fuzz_targets/fuzz_my_target.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = qv_core::function_to_fuzz(data);
});
```

Then add to `crates/qv-core/fuzz/Cargo.toml`:

```toml
[[bin]]
name = "fuzz_my_target"
path = "fuzz_targets/fuzz_my_target.rs"
test = false
doc = false
bench = false
```
