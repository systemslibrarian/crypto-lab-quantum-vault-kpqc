/*
 * smaug_exports.c — Emscripten-exported wrapper for SMAUG-T Level 1 KEM.
 *
 * Compile with -DSMAUG_MODE=1 to select the 128-bit security parameter set.
 * export_name attribute is the correct mechanism for Emscripten 5 / wasm-ld.
 */

/*
 * Include kem.h (not api.h) to get the correct void return type for keypair.
 * kem.h applies the SMAUG_NAMESPACE macro so we get cryptolab_smaug1_* names.
 * api.h has a conflicting int declaration for keypair — do not include it.
 */
#include "kem.h"
#include <emscripten/emscripten.h>

/*
 * Key Generation
 * pk: output — cryptolab_smaug1_PUBLICKEYBYTES (672) bytes
 * sk: output — cryptolab_smaug1_SECRETKEYBYTES (832) bytes
 * Returns 0 on success.
 */
__attribute__((export_name("smaug_keypair"), used, visibility("default")))
int smaug_keypair(uint8_t *pk, uint8_t *sk) {
    cryptolab_smaug1_crypto_kem_keypair(pk, sk);
    return 0;
}

/*
 * Encapsulate: generate ciphertext + shared secret from a public key.
 * ct: output — cryptolab_smaug1_CIPHERTEXTBYTES (672) bytes
 * ss: output — cryptolab_smaug1_BYTES (32) bytes
 * pk: input  — cryptolab_smaug1_PUBLICKEYBYTES (672) bytes
 */
__attribute__((export_name("smaug_encapsulate"), used, visibility("default")))
int smaug_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return cryptolab_smaug1_crypto_kem_enc(ct, ss, pk);
}

/*
 * Decapsulate: recover shared secret from ciphertext + secret key.
 * ss:  output — cryptolab_smaug1_BYTES (32) bytes
 * ct:  input  — cryptolab_smaug1_CIPHERTEXTBYTES (672) bytes
 * sk:  input  — cryptolab_smaug1_SECRETKEYBYTES (832) bytes
 */
__attribute__((export_name("smaug_decapsulate"), used, visibility("default")))
int smaug_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return cryptolab_smaug1_crypto_kem_dec(ss, ct, sk);
}

/* Size accessors — allows TypeScript to query buffer sizes at runtime */
__attribute__((export_name("smaug_publickeybytes"),   used, visibility("default"))) int smaug_publickeybytes(void)    { return PUBLICKEY_BYTES; }
__attribute__((export_name("smaug_secretkeybytes"),   used, visibility("default"))) int smaug_secretkeybytes(void)    { return KEM_SECRETKEY_BYTES; }
__attribute__((export_name("smaug_ciphertextbytes"),  used, visibility("default"))) int smaug_ciphertextbytes(void)   { return CIPHERTEXT_BYTES; }
__attribute__((export_name("smaug_sharedsecretbytes"),used, visibility("default"))) int smaug_sharedsecretbytes(void) { return CRYPTO_BYTES; }
