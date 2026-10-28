# SMAUG-T WASM Side-Channel Evidence Review

**Original review:** March 15, 2026
**Evidence rechecked:** October 23, 2026
**Scope:** Active SMAUG-T Level 1 browser artifact (`web-demo/public/smaug.wasm`)
**Status:** Source-level mitigations verified; constant-time behavior of the compiled WASM is not proven

## Conclusion

The pinned SMAUG-T C source uses an XOR-accumulation comparison and arithmetic
conditional move in the Fujisaki-Okamoto decapsulation path. The exact clean
build recorded by `wasm/reproduction.json` uses `-O1`, disables tree and SLP
vectorization, and reproduces the active loader and WASM bytes. The shipped
module exports `smaug_secure_zeroize`, and the TypeScript wrapper calls it for
secret-key and shared-secret allocations on every exit.

Those are useful controls, but they are not a proof that the compiled WASM is
constant-time. No retained browser timing result, compiled-code audit, or
cross-device measurement establishes that ciphertext validity is
indistinguishable in the deployed artifact. The earlier report's stronger
claims—including “all mitigations implemented,” “constant-time,” and “no
additional code changes required”—went beyond the retained evidence.

## Evidence boundary

| Evidence | What it establishes | What it does not establish |
|---|---|---|
| `wasm/reproduction.json` and `wasm/reproduce.py` | Immutable source/wrapper pins, exact compiler image and command, and byte-for-byte reproduction of the active artifacts | Original publisher identity, algorithm security, or constant-time execution |
| Pinned official source archive `hmchoe0528/SMAUG-T_public@2c039df23134a2de3c7aa86a4904c9a4734f9def` | The source corresponding to the active artifact; the archive SHA-256 is `2a202ba4fb3a4946d6d028aef180a1fc1637d78bdc0fe9200f6e30f2c4c71107` | That source-level control flow survives compilation without relevant timing differences |
| Active WASM SHA-256 `349f4bd2c63d3ecdbc8b805148ffc407b119d5eb4de3a4c9e74fc6d842f67838` | Identity of the bytes evaluated and deployed | A security property by itself |
| `web-demo/tests/wasm-contract.node.mjs` | Required runtime exports exist, including `smaug_secure_zeroize` | That overwrites happen in every browser failure mode without application tests |
| `web-demo/smaug-timing-harness.html` | A tool that can collect local measurements | Evidence of a result until its raw samples, environment, analysis, and threshold are retained |

The vendor tree is intentionally not committed in this checkout. Source claims
must be checked against the authenticated archive and manifest rather than a
nonexistent `wasm/vendor/smaug-t` directory.

## Verified source-level controls

The pinned `verify.c` compares every byte and accumulates differences without
an early exit:

```c
uint8_t r = 0;
for (i = 0; i < len; i++)
    r |= a[i] ^ b[i];
return (-(uint64_t)r) >> 63;
```

Its conditional move visits every output byte and selects arithmetically:

```c
b = -b;
for (i = 0; i < len; i++)
    r[i] ^= b & (r[i] ^ x[i]);
```

The pinned `crypto_kem_dec` re-encrypts, calls `verify`, derives the fallback
secret, and calls `cmov`; it does not call `randombytes` during decapsulation.
These observations reduce obvious source-level validity branches. They do not
rule out timing introduced by the rest of the implementation, Emscripten,
the WebAssembly engine, allocation, or host/browser behavior.

## Active build and memory controls

The exact active SMAUG command in `wasm/reproduction.json` uses:

- Emscripten 5.0.3 from the digest-pinned Linux amd64 compiler image recorded in the manifest;
- `-O1`, `-fno-tree-vectorize`, `-fno-slp-vectorize`, and `-DNDEBUG`;
- 16 MiB initial memory with memory growth allowed; and
- an explicit export list that includes `smaug_secure_zeroize`.

The previous report described 4 MiB as the deployed heap. That value belongs
to the current development recipe in `wasm/build.sh`; the reproducing command
for the active artifact uses 16 MiB. Flags such as `-O1` and disabled
vectorization are defense-in-depth choices, not a constant-time attestation.

At the TypeScript boundary, `smaug.ts` validates public-key, ciphertext, and
secret-key lengths before calling WASM. Temporary secret-key and shared-secret
allocations are cleared through the C export in `finally` blocks, then freed.
The JavaScript copies returned to `keywrap.ts` are also cleared in `finally`
blocks after Web Crypto imports or operations complete. Browser engines and OS
memory can retain additional copies, so this remains an educational demo rather
than a hardened key-management boundary.

## Remaining work before a production claim

1. Run the timing harness on representative x86 and ARM systems and retain raw interleaved samples, browser/OS versions, warm-up policy, and statistical analysis.
2. Inspect the compiled decapsulation path (not only C source) after every compiler or source change.
3. Define an acceptance threshold and negative control before collecting measurements.
4. Re-run exact artifact reproduction and all functional browser tests whenever the WASM bytes change.
5. Keep the TypeScript wrong-password versus valid-password/tampered-ciphertext timing distinction outside any remote oracle boundary.

Until that evidence exists, describe the implementation as having reviewed
source-level mitigations and reproducible bytes—not as proven constant-time.
