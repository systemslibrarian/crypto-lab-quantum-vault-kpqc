# Test Strategy

This document describes the test layers used by Quantum Vault. Test totals are
not copied here because they change as cases are added; the test-runner summaries
from the exact commit under review are authoritative.

## Test Inventory

| Layer | Location | What it covers |
|-------|----------|----------------|
| Rust unit tests | `crates/qv-core/src/` | Constants, algorithm registry, container parsing, Shamir arithmetic and feature boundaries |
| Rust integration tests | `crates/qv-core/tests/` | Vectors, properties, tampering, malformed corpus inputs, nonce behavior, zeroization paths and native-reference differential checks |
| Rust fuzz targets | `crates/qv-core/fuzz/fuzz_targets/` | Eight parser, AEAD, decrypt, KEM, signature, Shamir and WASM API boundaries |
| Browser unit tests | `web-demo/src/**/__tests__/*.test.ts` | Shamir, pipeline, wrapping cleanup, serialization, trust-boundary text and state validation |
| Node control tests | `web-demo/tests/*.node.mjs` | Toolchain, publish-request, active WASM contract and workflow-policy controls |
| Browser integration tests | `web-demo/e2e/*.spec.ts` | Production-build behavior, reconstruction evidence, signature trust, keyboard/focus, contrast and accessibility |
| WASM build tests | `wasm/tests/` | Fail-closed preflight and source-reproduction controls |
| Rust doc tests | `crates/qv-core/src/lib.rs` | Public API examples |

## Property-Based Tests (`proptest`)

Property tests exercise invariants over generated inputs.

### Shamir properties

- **Roundtrip completeness:** `split_secret(s) -> reconstruct_secret() == s`.
- **Threshold sufficiency:** any valid set of at least `t` distinct shares
  reconstructs the secret.
- **Under-threshold privacy:** conditioned on fewer than `t` shares, every
  candidate secret remains equally likely in the ideal scheme. A reconstruction
  attempt is not required to differ from the real secret; equality can occur by
  chance, so tests check distributions/invariants rather than asserting
  inequality for every sample.
- **Order independence:** share order does not affect reconstruction.
- **Share shape:** lengths and 1-based indices remain valid and unique.
- **Malformed inputs:** zero or duplicate indices and inconsistent share lengths
  are rejected.

### Pipeline and container properties

- Encrypt/decrypt round trips recover the original plaintext.
- Repeated encryption uses fresh container identities/nonces and yields distinct
  containers with overwhelming probability.
- Ciphertext, signature and signed-metadata changes are rejected.
- Serialization and deserialization preserve a valid container.
- Declared algorithm identifiers must match the selected backend before backend
  operations run.

## Fuzz Targets

| Target | Primary boundary |
|--------|------------------|
| `fuzz_aead_protect` | AEAD inputs and nonce/key handling |
| `fuzz_container_parse` | Malformed, truncated and oversized serialized containers |
| `fuzz_decrypt_pipeline` | Full rejection/decryption path |
| `fuzz_kem_handshake` | KEM key/ciphertext length and handshake boundaries |
| `fuzz_shamir_reconstruct` | Invalid share sets, indices and lengths |
| `fuzz_shamir_roundtrip` | Generated split/reconstruction parameters |
| `fuzz_signature_verify` | Signature/public-key/message boundaries |
| `fuzz_wasm_api` | Error-only WASM scaffold input boundaries |

Install `cargo-fuzz`, then run a target from `crates/qv-core`:

```bash
cargo install cargo-fuzz --locked
cd crates/qv-core
cargo +nightly fuzz run fuzz_container_parse -- -max_total_time=60
```

To run every current target locally:

```bash
cd crates/qv-core
for target in \
  fuzz_aead_protect \
  fuzz_container_parse \
  fuzz_decrypt_pipeline \
  fuzz_kem_handshake \
  fuzz_shamir_reconstruct \
  fuzz_shamir_roundtrip \
  fuzz_signature_verify \
  fuzz_wasm_api
do
  cargo +nightly fuzz run "$target" -- -max_total_time=30
done
```

## Continuous Integration

`.github/workflows/deploy-pages.yml` runs on pull requests to `main`, pushes to
`main` and manual dispatches. Its unprivileged gates include:

1. Rust workspace, targeted security, `wasm`-feature and no-default-feature
   tests; release feature guards; Clippy; formatting; short boundary fuzz runs;
   RustSec; and `cargo-deny`.
2. Python WASM preflight/reproduction-control tests, exact committed-WASM
   checksums, and web unit/control, lint and production-build checks on Node
   22, 24 and 26.
3. Playwright against the production bundle on Linux Chromium.
4. A clean, digest-pinned rebuild of the SMAUG-T and HAETAE artifacts from
   immutable source archives with exact four-artifact comparison, plus native
   Level 3 / Mode 3 KEM/signature round trips and tamper rejection from those
   same authenticated inputs.

Only a non-pull-request run that passes every gate retains the tested site and
passes it to the no-checkout Pages jobs. Repository source never executes with
Pages/OIDC write authority.

`.github/workflows/fuzz.yml` builds all eight fuzz targets on every pull request
and on relevant pushes to `main`. It executes 30-second smoke runs for all eight
targets only on a matching push to `main`. It is not a scheduled workflow.

## Coverage Gaps

| Gap | Status |
|-----|--------|
| Mutation testing (`cargo-mutants`) | Not configured |
| Miri/allocator-assisted memory diagnostics | Not configured; requires a suitable nightly/tooling environment |
| Conditional native KpqC differential path | CI downloads hash-pinned public captures and checks primitive round trips and tamper rejection; a full upstream implementation audit and end-to-end native CLI exercise remain out of scope |
| Browser/platform matrix | CI exercises Linux Chromium, not every browser and operating system |
| Production security assurance | Out of scope; passing tests do not turn the educational demo into hardened software |

## Running the Main Gates Locally

```bash
# Rust
cargo test --workspace
cargo test -p qv-core --no-default-features
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Native KpqC primitive gate (paths contain one extracted versioned source tree)
SMAUG_T_SRC=/path/to/smaug-parent \
HAETAE_SRC=/path/to/haetae-parent \
  cargo test -p qv-core --no-default-features --features kpqc-native \
    --test differential_tests

# WASM build controls
python3 -B -m unittest discover -s wasm/tests -v

# Web
cd web-demo
npm ci
npm test
npm run lint -- --max-warnings=0
npm run build
npm run test:e2e -- --retries=0
```

The clean source-reproduction command requires the immutable archives named in
`wasm/PROVENANCE.md`; CI is the routine authority for that network- and
container-dependent gate.

## Test Vector Sources

- **AES-256-GCM:** NIST SP 800-38D/CAVP vectors.
- **Shamir SSS:** deterministic vectors and generated invariants over this
  implementation's GF(256) field polynomial `0x11d`.
- **SMAUG-T / HAETAE:** NIST PQC KAT files do not apply to these KpqC
  algorithms. Coverage uses round trips, tamper tests and, when authenticated
  external sources are supplied, differential checks against the pinned KpqC
  reference implementations. The `dev-backend` SHA-256/XOR implementation is
  test-only and has no production-security claim.

## Adding New Tests

### Property test

Add a focused property to the relevant integration file:

```rust
proptest! {
    #[test]
    fn my_new_property(input in strategy) {
        let result = function_under_test(&input).map_err(to_test_err)?;
        prop_assert!(invariant(result));
    }
}
```

### Fuzz target

Create `crates/qv-core/fuzz/fuzz_targets/fuzz_my_target.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = qv_core::function_to_fuzz(data);
});
```

Then register it in `crates/qv-core/fuzz/Cargo.toml` and add it to both CI fuzz
target lists. A target that exists locally but is absent from CI is incomplete.
