# Quantum Vault — Implementation Notes

**Version:** 1.1
**Date:** 2026-10-23
**Applies to:** Web demo v5.1 (real KpqC WASM)

---

## Overview

The web demo uses SMAUG-T and HAETAE reference C implementations. On
2026-10-11, clean builds with an immutable Emscripten 5.0.3 image reproduced
both active loaders and both WASM files byte for byte. This establishes a
reproducing environment, not the original publisher's compiler. See
[the source pins, recipes and evidence](../wasm/PROVENANCE.md).

The compilation examples below describe historical development recipes and
do **not** reproduce the complete currently shipped pair. The active SMAUG
uses the historical `getentropy` shim and 16 MiB initial memory; the active
HAETAE uses the earlier wrapper, `-O2`, 32 MiB initial memory and a 2 MiB
stack. The exact source-backed commands are in `wasm/reproduction.json`.
Optimization flags, successful round trips and byte identity do not prove
constant-time behavior or eliminate allocator timing variation.

---

## 1. Compilation Pipeline

### 1.1 Prerequisites

```
emsdk 5.0.3 (emcc and em++ must be on PATH)
source ~/emsdk/emsdk_env.sh
```

The vendor C sources are external inputs and are not committed under
`wasm/vendor/` in this checkout. The exact active-artifact source archives and
historical wrappers are pinned in `wasm/reproduction.json`. The examples below
show the separate development recipe, where browser-incompatible platform code
is replaced by `wasm/src/randombytes_wasm.c`.

### 1.2 SMAUG-T Level 1

```bash
emcc \
  -O1 \
  -fno-tree-vectorize \
  -fno-slp-vectorize \
  -DNDEBUG \
  -DSMAUG_MODE=1 \
  -I"wasm/vendor/smaug-t/reference_implementation/include" \
  [13 vendor .c files] \
  wasm/src/randombytes_wasm.c \
  wasm/src/smaug_exports.c \
  -s WASM=1 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME='createSmaugModule' \
  -s ENVIRONMENT='web,node' \
  -s INITIAL_MEMORY=4194304 \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s EXPORTED_RUNTIME_METHODS='["cwrap","getValue"]' \
  -o wasm/dist/smaug.js
```

**Timing-hardening flags in this development recipe:**
- `-O1`: Reduces some aggressive transformations; it does not establish constant-time execution
- `-fno-tree-vectorize -fno-slp-vectorize`: Disable two forms of auto-vectorization as defense in depth
- `-DNDEBUG`: Disable assert() calls in reference implementations
- `-s INITIAL_MEMORY=4194304`: Pre-allocate a 4 MiB heap; this does not eliminate allocator or host timing jitter

`-DSMAUG_MODE=1` selects the Level 1 (128-bit PQC) parameter set.  The
reference implementation's preprocessor guards gate the key-size constants on
this macro.

### 1.3 HAETAE Mode 2

```bash
emcc \
  -O1 \
  -fno-tree-vectorize \
  -fno-slp-vectorize \
  -DNDEBUG \
  -I"wasm/vendor/haetae/HAETAE-1.1.2/reference_implementation/include" \
  [15 vendor .c files] \
  wasm/src/randombytes_wasm.c \
  wasm/src/haetae_exports.c \
  -s WASM=1 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME='createHaetaeModule' \
  -s ENVIRONMENT='web,node' \
  -s INITIAL_MEMORY=4194304 \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s EXPORTED_RUNTIME_METHODS='["cwrap","getValue"]' \
  -o wasm/dist/haetae.js
```

HAETAE 1.1.2 defaults to Mode 2 (128-bit PQC) when compiled without an explicit
mode override.  The mode is not selectable by a preprocessor macro in this
release; it is set by the parameter files included from the reference
implementation directory.

### 1.4 Build Outputs

| File | Destination in web-demo |
|------|------------------------|
| `wasm/dist/smaug.js` | `web-demo/src/crypto/wasm/smaug.js` |
| `wasm/dist/smaug.wasm` | `web-demo/public/smaug.wasm` |
| `wasm/dist/haetae.js` | `web-demo/src/crypto/wasm/haetae.js` |
| `wasm/dist/haetae.wasm` | `web-demo/public/haetae.wasm` |

The compiled binaries are committed to the repository so that CI and GitHub
Pages deployment do not require a C toolchain.

---

## 2. Exported Functions

### 2.1 SMAUG-T (`smaug_exports.c`)

The export shim includes `kem.h` (not `api.h`) to obtain the correct
`void`-return signature for `crypto_kem_keypair`.  Using `api.h` would introduce
a conflicting `int`-return declaration.

| Export | Signature | Description |
|--------|-----------|-------------|
| `smaug_keypair` | `(uint8_t *pk, uint8_t *sk) → int` | Key generation; 0 on success |
| `smaug_encapsulate` | `(uint8_t *ct, uint8_t *ss, const uint8_t *pk) → int` | Generate CT + SS from PK |
| `smaug_decapsulate` | `(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) → int` | Recover SS from CT + SK |
| `smaug_publickeybytes` | `(void) → int` | Returns 672 |
| `smaug_secretkeybytes` | `(void) → int` | Returns 832 |
| `smaug_ciphertextbytes` | `(void) → int` | Returns 672 |
| `smaug_sharedsecretbytes` | `(void) → int` | Returns 32 |
| `smaug_secure_zeroize` | `(uint8_t *buf, size_t len) → void` | Secure memory zeroing (volatile, cannot be elided) |

All exports use `__attribute__((export_name(...), used, visibility("default")))`,
which is the correct mechanism for Emscripten 5 / wasm-ld (the older
`EMSCRIPTEN_KEEPALIVE` macro is not used).

### 2.2 HAETAE (`haetae_exports.c`)

HAETAE 1.1.2 follows the FIPS 204–style context-string API.  The shim passes
`(NULL, 0)` as the context, which is equivalent to the plain message API.

| Export | Signature | Description |
|--------|-----------|-------------|
| `haetae_keypair` | `(uint8_t *vk, uint8_t *sk) → int` | Key generation; 0 on success |
| `haetae_sign` | `(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) → int` | Detached sign; 0 on success |
| `haetae_verify` | `(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *vk) → int` | 0 if valid |
| `haetae_publickeybytes` | `(void) → int` | Returns 992 |
| `haetae_secretkeybytes` | `(void) → int` | Returns 1408 |
| `haetae_sigbytes` | `(void) → int` | Returns 1474 (maximum) |
| `haetae_secure_zeroize` | `(uint8_t *buf, size_t len) → void` | Present in the current development wrapper; **absent from the active shipped WASM** |

`haetae_sign` writes the actual signature length into `*siglen`.  Since wasm32
uses 32-bit `size_t`, TypeScript reads this 4-byte value with `getValue(ptr,
'i32')`.

---

## 3. Randomness (`randombytes_wasm.c`)

The reference implementations call `randombytes(out, outlen)` internally.  Both
vendor trees include their own `randombytes.c` that calls POSIX `getrandom()` or
`/dev/urandom`, which do not exist in the browser sandbox.

`wasm/src/randombytes_wasm.c` replaces these by appearing last on the compiler
command line, which causes the linker to resolve the `randombytes` symbol from
this file instead.

```c
EM_JS(void, js_randombytes, (uint8_t *buf, size_t len), {
    crypto.getRandomValues(new Uint8Array(Module.HEAPU8.buffer, buf, len));
});

int randombytes(uint8_t *out, size_t outlen) {
    js_randombytes(out, outlen);
    return 0;
}
```

`EM_JS` emits a JavaScript function that is inlined into the generated `.js`
loader.  It writes directly into the Emscripten heap (`Module.HEAPU8.buffer`)
at the pointer passed from C.  `crypto.getRandomValues` is available in all
modern browsers and in Node.js ≥ 19 (used for `vitest`).

The shim also provides no-op stubs for `randombytes_init` and
`AES256_CTR_DRBG_Update`, which appear in HAETAE's `randombytes.h` for KAT test
generation and are never called in the browser build.

---

## 4. Memory Management

Emscripten compiles to a flat 32-bit address space (wasm32).  All pointers are
32-bit offsets into `Module.HEAPU8.buffer`.

**Caller-allocates pattern:**  
The TypeScript wrappers (`smaug.ts`, `haetae.ts`) allocate output buffers before
calling any WASM function:

```typescript
const pk = smaugMod._malloc(smaugMod.smaug_publickeybytes());
const sk = smaugMod._malloc(smaugMod.smaug_secretkeybytes());
smaugMod.smaug_keypair(pk, sk);
const pkBytes = smaugMod.HEAPU8.slice(pk, pk + PK_BYTES);
smaugMod._free(pk);
smaugMod._free(sk);
```

`_malloc` / `_free` are Emscripten's wrappers around the WASM heap allocator.
The TypeScript wrappers free their temporary allocations after copying output
into JavaScript arrays. SMAUG explicitly calls its secure-zeroize export for
secret buffers. The active shipped HAETAE WASM has no
`haetae_secure_zeroize` export, so the TypeScript wrapper overwrites secret
allocations through `HEAPU8.fill()` before freeing them. That fallback is
better than freeing alone but is best-effort: unlike a volatile C routine, the
repository cannot prove a JavaScript engine will preserve the write as an
erasure boundary. JavaScript array copies have a separate lifetime and are
also cleared by their callers after use.

The current development recipe's `INITIAL_MEMORY=4194304` pre-allocates a 4 MiB
heap and still enables memory growth. The active artifacts use the distinct
initial-memory values recorded in `wasm/reproduction.json` (16 MiB for SMAUG-T
and 32 MiB for HAETAE); pre-allocation reduces one source of allocator noise but
does not establish constant-time behavior.

---

## 5. Module Loading

Application startup calls `initCrypto()`, which initializes both WASM modules in
parallel before the vault is loaded or rendered. Each wrapper retains its module
instance for subsequent synchronous crypto calls:

```typescript
// web-demo/src/crypto/smaug.ts (abridged)
let smaugModule: SmaugModule | null = null;

export async function initSmaug(): Promise<void> {
  const createModule = (await import('./wasm/smaug.js')).default;
  // Fetch `${import.meta.env.BASE_URL}/smaug.wasm`, then instantiate it.
  smaugModule = await createModule({ wasmBinary });
}
```

The SMAUG wrapper explicitly fetches `${BASE_URL}/smaug.wasm` with `no-store`
and supplies those bytes to the Emscripten factory. The HAETAE factory resolves
`${BASE_URL}/haetae.wasm` through `locateFile()` and the browser's ordinary fetch
path. Neither artifact is fetched on each vault operation; the initialized
module objects remain cached in their wrappers.

`MODULARIZE=1` wraps the entire Emscripten runtime in a factory function rather
than polluting the global scope — necessary in a bundled ES-module environment.

`ENVIRONMENT='web,node'` instructs Emscripten to emit fetch-based WASM loading
(for browsers) and `fs.readFile`-based loading (for Node.js), allowing the same
`.js` loader to work in both `vitest` and the browser.

---

## 6. Parameter Choices

### 6.1 Level 1 / Mode 2 for the Web Demo

The web demo uses Level 1 (SMAUG-T) and Mode 2 (HAETAE) — the lowest parameter
set of each algorithm. The Rust crates define a separate Level 3 / Mode 3 FFI
path, but it runs only when authenticated external C sources are supplied;
the checked-in `kpqc-wasm` feature is an error-only scaffold.

| Artifact | Level 1 / Mode 2 | Level 3 / Mode 3 |
|----------|-----------------|-----------------|
| SMAUG-T PK | 672 B | 1 088 B |
| SMAUG-T SK | 832 B | 1 312 B |
| SMAUG-T CT | 672 B | 992 B |
| HAETAE PK | 992 B | 1 472 B |
| HAETAE SK | 1 408 B | 2 112 B |
| HAETAE max sig | 1 474 B | 2 349 B |

The web demo stores three `WrappedShare` records per container, each containing
a PK, a wrapped SK, a KEM ciphertext, and two AES-GCM outputs.  Using Level 1 /
Mode 2 reduces per-box storage by roughly 3 × (400 B PK + 480 B SK + 320 B CT)
≈ 3.6 KB per box.  In a `localStorage`-backed app this is not critical, but
keeping the WASM binary smaller also reduces initial load time.

The parameter sets do **not** target the same strength. SMAUG-T Level 1 targets NIST PQC category 1
(comparable to an exhaustive key search on AES-128) and SMAUG-T Level 3 targets
category 3 (comparable to AES-192).  HAETAE Mode 2 targets category 2 and Mode 3
targets category 3.  A composite is only as strong as its weakest component, so
the web demo's stated post-quantum target is category 1 (set by SMAUG-T Level
1). A separately supplied and successfully built native Level 3 / Mode 3 path
would target category 3. CI compiles authenticated, pinned public source
captures and checks the native primitive round trips and tamper rejection; it
does not perform a full upstream implementation audit or an end-to-end native
CLI exercise. AES-256-GCM is configured in both designs.

### 6.2 GF(2⁸) Polynomial 0x11d

The Shamir implementation uses the primitive polynomial x⁸ + x⁴ + x³ + x² + 1
(`0x11d`) to define GF(2⁸).  The element 2 is a primitive root of this field,
meaning it has multiplicative order 255.  This allows a compact LOG/EXP table
construction where `LOG[EXP[i]] = i` for all i ∈ {0..254}.

The polynomial `0x11b` (the AES polynomial x⁸ + x⁴ + x³ + x + 1) was used in
an earlier version.  Generator 2 has order **51** in that field (not 255),
causing the LOG table to fill with repeated cycles and silently corrupting all
Shamir round-trips for non-trivial secrets.  See `docs/specification.md §4.1`
for the formal field definition.

---

## 7. Known Limitations

**No key persistence:** The HAETAE signing keypair is ephemeral — generated at
seal time and stored only as `sigPublicKey` in the container.  The SK is
discarded after signing. Verification establishes consistency under the included
key, not that it is the original sealer's key. Anyone can generate a new keypair
and re-sign changed public container data. No independent key pin or identity
binding is checked; this replacement alone does not decrypt the encrypted shares.

**Browser-local storage only:** `VaultState` is serialised to `localStorage`
under the key `quantum-vault-data` (`src/vault/state.ts`).  Note that this is
`localStorage`, not `sessionStorage` — sealed boxes therefore **survive** closing
the tab and the browser, and persist per-origin until "Clear vault" is used or
the profile is wiped.  Anyone with access to the browser profile can read the
stored containers offline; see the offline-brute-force row in
`docs/threat-model.md §5`.  This is intentional for the demo (the boxes are meant
to still be there on your next visit); a production deployment would persist to
an encrypted backend instead.

**No HSM or secure enclave:** Key material exists within the browser process
across JavaScript typed arrays, WASM linear memory and the browser's Web Crypto
implementation during operations. A compromised browser extension or malicious
same-origin script may be able to reach relevant inputs or outputs. The demo
assumes a trusted browser context, and best-effort overwrites are not a browser-
process erasure guarantee.

**PBKDF2 iteration count:** 600 000 iterations of SHA-256 is used for new
deposits. This matches the
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
recommendation for PBKDF2-HMAC-SHA256 as checked on 2026-10-23.
[NIST SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final) (2010)
recommends at least 1 000 iterations and selecting as many as user-acceptable
performance permits. Legacy v2 containers with 100 000 iterations are still
supported for backward compatibility. The iteration count is stored per-share,
allowing gradual migration.

**WASM binary size:** The committed `smaug.wasm` is 22,345 bytes and
`haetae.wasm` is 42,683 bytes. They are fetched during application startup;
SMAUG uses an explicit `no-store` request while HAETAE follows the browser's
ordinary hosting/cache policy.

**No streaming decrypt:** The entire ciphertext is held in memory.  The current
design is appropriate for short secrets (message strings); it is not suitable
for large file encryption without rearchitecting the pipeline.
