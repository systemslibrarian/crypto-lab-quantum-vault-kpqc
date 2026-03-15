// TypeScript wrapper for SMAUG-T Level 1 KEM compiled to WebAssembly.
// All WASM memory management is contained here — callers receive plain Uint8Arrays.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let smaugModule: any = null;

export async function initSmaug(): Promise<void> {
  // Dynamic import of the Emscripten-generated JS loader.
  // Vite copies the .wasm file to public/ and the loader fetches it from there.
  const createModule = (await import('./wasm/smaug.js')).default;
  smaugModule = await createModule({
    // Tell Emscripten where the .wasm file lives at runtime.
    locateFile: (path: string) => {
      const base = import.meta.env.BASE_URL ?? '/';
      return base.replace(/\/$/, '') + '/' + path;
    },
  });
}

function assertReady(): void {
  if (!smaugModule) throw new Error('SMAUG-T WASM not initialized — call initSmaug() first');
}

/** Generate a SMAUG-T Level 1 keypair (PK: 672 B, SK: 832 B). */
export function smaugKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  assertReady();
  const pkSize = smaugModule._smaug_publickeybytes() as number;
  const skSize = smaugModule._smaug_secretkeybytes() as number;
  const pkPtr = smaugModule._malloc(pkSize) as number;
  const skPtr = smaugModule._malloc(skSize) as number;
  try {
    const ret = smaugModule._smaug_keypair(pkPtr, skPtr) as number;
    if (ret !== 0) throw new Error(`SMAUG-T keygen failed (ret=${ret})`);
    const publicKey = new Uint8Array(smaugModule.HEAPU8.buffer as ArrayBuffer, pkPtr, pkSize).slice();
    const secretKey = new Uint8Array(smaugModule.HEAPU8.buffer as ArrayBuffer, skPtr, skSize).slice();
    return { publicKey, secretKey };
  } finally {
    // Use C-level secure zeroing that cannot be optimized away by JS engines
    smaugModule._smaug_secure_zeroize(pkPtr, pkSize);
    smaugModule._free(pkPtr);
    smaugModule._smaug_secure_zeroize(skPtr, skSize);
    smaugModule._free(skPtr);
  }
}

/**
 * Encapsulate: generate a shared secret and its ciphertext from a public key.
 * Returns: ciphertext (672 B) + sharedSecret (32 B).
 */
export function smaugEncapsulate(publicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
  assertReady();
  const ctSize = smaugModule._smaug_ciphertextbytes() as number;
  const ssSize = smaugModule._smaug_sharedsecretbytes() as number;
  const pkSize = smaugModule._smaug_publickeybytes() as number;
  if (publicKey.length !== pkSize) {
    throw new Error(`Invalid SMAUG-T public key length: ${publicKey.length} (expected ${pkSize})`);
  }
  const pkPtr = smaugModule._malloc(pkSize) as number;
  const ctPtr = smaugModule._malloc(ctSize) as number;
  const ssPtr = smaugModule._malloc(ssSize) as number;
  try {
    smaugModule.HEAPU8.set(publicKey, pkPtr);
    const ret = smaugModule._smaug_encapsulate(ctPtr, ssPtr, pkPtr) as number;
    if (ret !== 0) throw new Error(`SMAUG-T encapsulate failed (ret=${ret})`);
    return {
      ciphertext: new Uint8Array(smaugModule.HEAPU8.buffer as ArrayBuffer, ctPtr, ctSize).slice(),
      sharedSecret: new Uint8Array(smaugModule.HEAPU8.buffer as ArrayBuffer, ssPtr, ssSize).slice(),
    };
  } finally {
    // Use C-level secure zeroing that cannot be optimized away by JS engines
    smaugModule._smaug_secure_zeroize(pkPtr, pkSize);
    smaugModule._free(pkPtr);
    smaugModule._free(ctPtr);
    smaugModule._smaug_secure_zeroize(ssPtr, ssSize);
    smaugModule._free(ssPtr);
  }
}

/**
 * Decapsulate: recover the shared secret from a KEM ciphertext and secret key.
 * Returns: sharedSecret (32 B). Different SK → different (wrong) shared secret.
 */
export function smaugDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  assertReady();
  const ctExpected = smaugModule._smaug_ciphertextbytes() as number;
  const skExpected = smaugModule._smaug_secretkeybytes() as number;
  const ssSize = smaugModule._smaug_sharedsecretbytes() as number;
  if (ciphertext.length !== ctExpected) {
    throw new Error(`Invalid SMAUG-T ciphertext length: ${ciphertext.length} (expected ${ctExpected})`);
  }
  if (secretKey.length !== skExpected) {
    throw new Error(`Invalid SMAUG-T secret key length: ${secretKey.length} (expected ${skExpected})`);
  }
  const ctPtr = smaugModule._malloc(ciphertext.length) as number;
  const skPtr = smaugModule._malloc(secretKey.length) as number;
  const ssPtr = smaugModule._malloc(ssSize) as number;
  try {
    smaugModule.HEAPU8.set(ciphertext, ctPtr);
    smaugModule.HEAPU8.set(secretKey, skPtr);
    const ret = smaugModule._smaug_decapsulate(ssPtr, ctPtr, skPtr) as number;
    if (ret !== 0) throw new Error(`SMAUG-T decapsulate failed (ret=${ret})`);
    return new Uint8Array(smaugModule.HEAPU8.buffer as ArrayBuffer, ssPtr, ssSize).slice();
  } finally {
    smaugModule._free(ctPtr);
    // Use C-level secure zeroing that cannot be optimized away by JS engines
    smaugModule._smaug_secure_zeroize(skPtr, secretKey.length);
    smaugModule._free(skPtr);
    smaugModule._smaug_secure_zeroize(ssPtr, ssSize);
    smaugModule._free(ssPtr);
  }
}
