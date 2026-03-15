/*
 * haetae_exports.c — Emscripten-exported wrapper for HAETAE Mode 2 signatures.
 *
 * Compile with default HAETAE_CONFIG_MODE (HAETAE_MODE2 = 128-bit security level, NIST Level 1 equivalent).
 * export_name attribute is the correct mechanism for Emscripten 5 / wasm-ld.
 *
 * HAETAE 1.1.2 uses the context-string API (FIPS 204 style). We always pass
 * an empty context (NULL, 0) for normal operation.
 */

#include "api.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <emscripten/emscripten.h>

/*
 * Secure memory zeroing that the compiler cannot optimize away.
 * Uses volatile to prevent dead-store elimination.
 * This is critical for zeroizing secret keys in WASM heap.
 */
static void secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/*
 * Exported secure zeroing function for TypeScript to call.
 * TypeScript's HEAPU8.fill() can be optimized away by JS engines;
 * this C-level zeroing cannot be elided by Emscripten or the JS engine.
 */
__attribute__((export_name("haetae_secure_zeroize"), used, visibility("default")))
void haetae_secure_zeroize(uint8_t *buf, size_t len) {
    secure_memzero(buf, len);
}

/*
 * Key Generation
 * vk: output — CRYPTO_PUBLICKEYBYTES bytes
 * sk: output — CRYPTO_SECRETKEYBYTES bytes
 * Returns 0 on success.
 */
__attribute__((export_name("haetae_keypair"), used, visibility("default")))
int haetae_keypair(uint8_t *vk, uint8_t *sk) {
    return crypto_sign_keypair(vk, sk);
}

/*
 * Sign a message (detached signature).
 * sig:    output — up to CRYPTO_BYTES (1474) bytes
 * siglen: output — actual signature length (size_t, 4 bytes in wasm32)
 * m:      input  — message bytes
 * mlen:   input  — message length
 * sk:     input  — CRYPTO_SECRETKEYBYTES bytes
 * Returns 0 on success.
 */
__attribute__((export_name("haetae_sign"), used, visibility("default")))
int haetae_sign(uint8_t *sig, size_t *siglen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk) {
    /* Pass empty context string (ctx=NULL, ctxlen=0) */
    return crypto_sign_signature(sig, siglen, m, mlen, NULL, 0, sk);
}

/*
 * Verify a detached signature.
 * sig:    input — signature bytes
 * siglen: input — byte length of sig
 * m:      input — message bytes
 * mlen:   input — message length
 * vk:     input — CRYPTO_PUBLICKEYBYTES bytes
 * Returns 0 if valid, non-zero if invalid.
 */
__attribute__((export_name("haetae_verify"), used, visibility("default")))
int haetae_verify(const uint8_t *sig, size_t siglen,
                  const uint8_t *m, size_t mlen,
                  const uint8_t *vk) {
    /* Pass empty context string (ctx=NULL, ctxlen=0) */
    return crypto_sign_verify(sig, siglen, m, mlen, NULL, 0, vk);
}

/* Size accessors */
__attribute__((export_name("haetae_publickeybytes"), used, visibility("default"))) int haetae_publickeybytes(void) { return CRYPTO_PUBLICKEYBYTES; }
__attribute__((export_name("haetae_secretkeybytes"), used, visibility("default"))) int haetae_secretkeybytes(void) { return CRYPTO_SECRETKEYBYTES; }
__attribute__((export_name("haetae_sigbytes"),       used, visibility("default"))) int haetae_sigbytes(void)       { return CRYPTO_BYTES; }
