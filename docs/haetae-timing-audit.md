# HAETAE WASM Timing Side-Channel Audit

**Date:** March 15, 2026  
**Scope:** HAETAE Mode 2 WASM build (`haetae.wasm`)  
**Status:** ✅ All recommended mitigations implemented

---

## Executive Summary

This audit evaluated the HAETAE WASM build for timing side-channel vulnerabilities. The implementation follows best practices for constant-time compilation and memory handling. The inherent Fiat-Shamir with Aborts timing leak is documented and acceptable for the threat model (ephemeral single-use signature keys).

---

## File Inventory

| File | Lines | Purpose |
|------|-------|---------|
| `wasm/build.sh` | 121 | Emscripten build script with CT-hardening flags |
| `wasm/src/haetae_exports.c` | 87 | C export wrappers with secure zeroing |
| `wasm/src/randombytes_wasm.c` | 53 | RNG routing to `crypto.getRandomValues` |
| `web-demo/src/crypto/haetae.ts` | 97 | TypeScript WASM wrapper |
| `wasm/vendor/haetae/.../sign.c` | 558 | Vendor HAETAE signing implementation |

---

## Audit Findings

### 1. Build Flags (wasm/build.sh)

**Status:** ✅ Hardened

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
| `INITIAL_MEMORY=4194304` | Pre-allocates 4 MiB (no runtime heap growth) |

### 2. Secure Memory Zeroing (wasm/src/haetae_exports.c)

**Status:** ✅ Implemented

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

The `volatile` qualifier prevents compiler from optimizing away the zeroing operation. Exported as `_haetae_secure_zeroize()` and called from TypeScript after each signing operation.

### 3. TypeScript Boundary (web-demo/src/crypto/haetae.ts)

**Status:** ✅ Correct

```typescript
// After signature extraction
Module._haetae_secure_zeroize(skPtr, skBytes.length);
Module._free(skPtr);
```

Uses C-level secure zeroing instead of `HEAPU8.fill()` which could be optimized away by JS engines.

### 4. RNG Layer (wasm/src/randombytes_wasm.c)

**Status:** ✅ No timing leak

```c
EM_JS(void, randombytes, (uint8_t *buf, size_t len), {
    crypto.getRandomValues(HEAPU8.subarray(buf, buf + len));
});
```

**Critical Finding:** `randombytes()` is called **once per signature** at the start of signing, not inside the rejection loop. The `seed` is generated before entering the reject/retry logic (sign.c line 210). This eliminates the concern about variable RNG call counts leaking iteration count.

### 5. HAETAE Rejection Loop (vendor sign.c)

**Status:** ⚠️ Inherent leak (documented, acceptable)

```c
reject:
    // ... polynomial sampling and norm computations ...
    
    // Constant-time norm bound check using bit-shift
    if ((z2_sqnorm - (uint64_t)B2) >> 63) {
        goto reject;
    }
```

The Fiat-Shamir with Aborts paradigm inherently leaks iteration count through total signing time. This is a fundamental property of the algorithm, not an implementation flaw.

**Mitigation:** This leak is acceptable because:
1. Signature keys are ephemeral (generated fresh per vault operation)
2. Single-use pattern means attacker cannot collect multiple signatures
3. Documented in `docs/threat-model.md` §5.1

### 6. Hyperball Sampling (vendor polyfix.c)

**Status:** ✅ Constant-time per iteration

```c
static void polyfixveclk_sample_hyperball(...) {
    // Rejection sampling for uniform distribution
    // Each iteration is constant-time; only iteration count varies
}
```

Inner rejection loop for polynomial sampling is constant-time per iteration. Combined with the outer signing loop, contributes to total timing variance but does not leak additional secrets.

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
| Build optimization level | High | ✅ `-O1` (safe) |
| Auto-vectorization | Medium | ✅ Disabled |
| Memory zeroing | High | ✅ Volatile C-level |
| Heap pre-allocation | Medium | ✅ 4 MiB fixed |
| RNG call pattern | High | ✅ Once per signature |
| Rejection loop timing | Medium | ⚠️ Inherent, documented |
| TypeScript boundary | Medium | ✅ Uses C secure_zeroize |

---

## Conclusion

**No additional code changes are recommended.** The HAETAE WASM build is well-hardened against practical timing side-channels. The inherent Fiat-Shamir timing leak is acknowledged in the threat model and mitigated by the ephemeral single-use key architecture.

### Recommendations for Production

1. **Empirical validation:** Run timing harness across target browsers/devices
2. **Hardware diversity:** Test on both x86 and ARM (M1/M2) for SIMD variance
3. **Periodic re-audit:** Review after Emscripten or browser updates
