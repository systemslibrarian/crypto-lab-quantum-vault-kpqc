# HAETAE WASM Timing Side-Channel Audit

**Date:** March 15, 2026; evidence rechecked October 23, 2026
**Scope:** HAETAE Mode 2 WASM build (`haetae.wasm`)
**Status:** ⚠️ Source review only; several original deployment claims were incorrect

---

## Executive Summary

The March review mixed the current development recipe with the binary actually
served by the demo. The October evidence review reproduced the shipped bytes
and established that they use the historical `-O2` recipe, 32 MiB initial
memory, and a 2 MiB stack. The shipped module also lacks the
`haetae_secure_zeroize` export. The source-level rejection-loop analysis below
is still useful, but it is not empirical proof that the deployed WASM is
constant-time. The source has variable-work rejection loops; the size and
exploitability of any resulting timing signal remain unquantified. The demo
accepts that residual risk for ephemeral, single-use signing keys.

---

## File Inventory

| File | Purpose |
|------|---------|
| `wasm/build.sh` | Development recipe; not the shipped HAETAE command |
| `wasm/reproduction.json` | Exact command and identities that reproduce the shipped artifact |
| `wasm/src/haetae_exports.c` | Current development wrapper with secure-zeroing export |
| `wasm/src/randombytes_wasm.c` | Current development RNG shim; historical wrapper pin is recorded separately |
| `web-demo/src/crypto/haetae.ts` | TypeScript WASM wrapper with a best-effort fallback for the shipped artifact |
| HAETAE `sign.c` in the pinned archive | Vendor signing implementation enumerated by `wasm/reproduction.json` |

---

## Audit Findings

### 1. Build Flags (wasm/build.sh)

**Status:** ⚠️ Development recipe only

```bash
emcc ... \
  -O1 \
  -fno-tree-vectorize \
  -fno-slp-vectorize \
  -DNDEBUG \
  -s INITIAL_MEMORY=4194304 \
  ...
```

| Flag | Purpose |
|------|---------|
| `-O1` | Avoids aggressive optimizations that can break CT properties |
| `-fno-tree-vectorize` | Prevents auto-vectorization (SIMD variance) |
| `-fno-slp-vectorize` | Prevents superword-level parallelism |
| `-DNDEBUG` | Disables asserts (no secret-dependent branches) |
| `INITIAL_MEMORY=4194304` | Pre-allocates 4 MiB in the development recipe |

These are not the flags of the active artifact. The exact reproducing command
in `wasm/reproduction.json` uses `-O2`, `INITIAL_MEMORY=33554432`, and
`STACK_SIZE=2097152`, without the two anti-vectorization flags. None of those
flag choices by itself proves or disproves constant-time behavior.

### 2. Secure Memory Zeroing (wasm/src/haetae_exports.c)

**Status:** ⚠️ Present in current source, absent from the shipped binary

```c
static void secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

void haetae_secure_zeroize(uint8_t *ptr, size_t len) {
    secure_memzero(ptr, len);
}
```

The `volatile` qualifier is appropriate for the current development wrapper.
However, enumerating the active `web-demo/public/haetae.wasm` exports shows no
`haetae_secure_zeroize`, so this routine cannot be called in the deployed path.

### 3. TypeScript Boundary (web-demo/src/crypto/haetae.ts)

**Status:** ⚠️ Best-effort fallback

```typescript
// Prefer the C export when a future binary provides it.
if (Module._haetae_secure_zeroize) {
  Module._haetae_secure_zeroize(skPtr, skBytes.length);
} else {
  Module.HEAPU8.fill(0, skPtr, skPtr + skBytes.length);
}
Module._free(skPtr);
```

The current wrapper clears the allocation on every exit before freeing it. For
the shipped module this is a JavaScript typed-array write and therefore
best-effort, not the guaranteed volatile-C erasure claimed by the March review.

### 4. RNG Layer (wasm/src/randombytes_wasm.c)

**Status:** ✅ Source call pattern verified; not a whole-binary timing result

```c
EM_JS(void, randombytes, (uint8_t *buf, size_t len), {
    crypto.getRandomValues(HEAPU8.subarray(buf, buf + len));
});
```

`randombytes()` is called once per signature at the start of signing, not
inside the rejection loop. The seed is generated before entering the
reject/retry logic. This removes variable RNG call count as the source of the
iteration-count signal; it does not eliminate the rejection-loop timing or
establish constant-time behavior for the compiled binary.

### 5. HAETAE Rejection Loop (vendor sign.c)

**Status:** ⚠️ Variable-work source path; practical leakage not established

```c
reject:
    // ... polynomial sampling and norm computations ...
    
    // Norm-bound expression; a failed bound restarts the variable-work loop
    if ((z2_sqnorm - (uint64_t)B2) >> 63) {
        goto reject;
    }
```

The pinned source restarts this signing attempt when the bound check fails, so
the number of attempts is a variable-work signal at source level. This review
does not show how reliably total browser time reveals that count, whether the
signal is exploitable for key recovery, or that constant-work mitigations are
impossible. It therefore records a risk, not an established whole-artifact leak
or a general claim about every Fiat-Shamir-with-aborts implementation.

**Exposure reduction in this demo:**

1. A fresh signature keypair is generated for each vault seal.
2. Each secret key signs one message, reducing repeated traces under a single
   key; this does not prove that one trace is harmless.
3. The remaining uncertainty is documented in `docs/threat-model.md` §5.1.

### 6. Hyperball Sampling (vendor polyfix.c)

**Status:** ⚠️ Source-level review only

```c
static void polyfixveclk_sample_hyperball(...) {
    // Rejection sampling for uniform distribution
    // Rejection sampling loop; compiled timing requires separate evaluation
}
```

The reviewed source performs a repeated sampling loop. No whole-program claim
about fixed work or absence of secret-dependent timing follows from this
excerpt; the loop compounds the need for controlled compiled-artifact testing.

### 7. Timing Harness

**Status:** ✅ Available

A timing harness exists at `web-demo/timing-harness.html` for empirical validation:
- Histogram visualization
- CSV export for statistical analysis
- Configurable warm-up iterations
- Measures sign/verify operations

---

## Summary Table

| Area | Risk | Status |
|------|------|--------|
| Build optimization level | High | ⚠️ Shipped build is `-O2`; no constant-time conclusion from flags alone |
| Auto-vectorization | Medium | ⚠️ Disable flags are absent from the reproducing shipped command |
| Memory zeroing | High | ⚠️ Shipped binary lacks the C export; wrapper fallback is best-effort |
| Heap pre-allocation | Medium | ⚠️ Shipped artifact starts at 32 MiB and permits growth |
| RNG call pattern | High | ✅ Once per signature |
| Rejection loop timing | Unknown | ⚠️ Variable work observed in source; signal and exploitability unquantified |
| TypeScript boundary | Medium | ⚠️ Clears on all exits, with a JS fallback for current bytes |

---

## Conclusion

The available evidence does not justify calling the deployed artifact
constant-time or C-zeroized. This review corrected the wrapper so secret WASM
allocations are cleared on every exit and documented the fallback honestly;
replacing the shipped binary should require exact source reproduction, browser
behavior tests, and a new timing review. The source-level variable-work risk is
acknowledged in the threat model. Ephemeral single-use keys reduce repeated-key
exposure but do not constitute a side-channel proof.

### Recommendations for Production

1. **Empirical validation:** Run timing harness across target browsers/devices
2. **Hardware diversity:** Test on both x86 and ARM (M1/M2) for SIMD variance
3. **Periodic re-audit:** Review after Emscripten or browser updates
