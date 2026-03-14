/*
 * randombytes_wasm.c — replaces the native randombytes.c from both
 * SMAUG-T and HAETAE reference implementations when compiling to WebAssembly.
 *
 * Routes all randomness requests to JavaScript's crypto.getRandomValues()
 * via Emscripten's EM_JS macro.
 */

#include <stddef.h>
#include <stdint.h>
#include <emscripten.h>

EM_JS(void, js_randombytes, (uint8_t *buf, size_t len), {
    crypto.getRandomValues(new Uint8Array(Module.HEAPU8.buffer, buf, len));
});

/* SMAUG-T uses: int randombytes(uint8_t *x, size_t xlen) */
/* HAETAE uses:  int randombytes(uint8_t *out, size_t outlen) */
int randombytes(uint8_t *out, size_t outlen) {
    js_randombytes(out, outlen);
    return 0;
}

/*
 * HAETAE's randombytes.h also declares randombytes_init and
 * AES256_CTR_DRBG_Update for KAT test generation. These are no-ops
 * in the WASM build since we never run KAT tests from the browser.
 */
void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization_string,
                      int security_strength) {
    (void)entropy_input;
    (void)personalization_string;
    (void)security_strength;
}

void AES256_CTR_DRBG_Update(unsigned char *provided_data,
                             unsigned char *Key,
                             unsigned char *V) {
    (void)provided_data;
    (void)Key;
    (void)V;
}
