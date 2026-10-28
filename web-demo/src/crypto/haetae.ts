// TypeScript wrapper for HAETAE Mode 2 digital signatures compiled to WebAssembly.
// All WASM memory management is contained here — callers receive plain Uint8Arrays.

import type { EmscriptenModuleFactory, HaetaeModule } from './wasm-types';

let haetaeModule: HaetaeModule | null = null;

export async function initHaetae(): Promise<void> {
  const createModule = (await import('./wasm/haetae.js')).default as EmscriptenModuleFactory<HaetaeModule>;
  haetaeModule = await createModule({
    locateFile: (path: string) => {
      const base = import.meta.env.BASE_URL ?? '/';
      return base.replace(/\/$/, '') + '/' + path;
    },
  });
}

function assertReady(): void {
  if (!haetaeModule) throw new Error('HAETAE WASM not initialized — call initHaetae() first');
}

function getModule(): HaetaeModule {
  assertReady();
  return haetaeModule as HaetaeModule;
}

/**
 * Clear a WASM allocation before freeing it. The active historical HAETAE
 * binary lacks the C volatile-zero export present in current source, so its
 * fallback is best-effort HEAPU8 clearing rather than guaranteed erasure.
 */
function clearAllocation(module: HaetaeModule, ptr: number, length: number): void {
  if (module._haetae_secure_zeroize) {
    module._haetae_secure_zeroize(ptr, length);
  } else {
    module.HEAPU8.fill(0, ptr, ptr + length);
  }
}

/** Generate a HAETAE Mode 2 signing keypair (PK: 992 B, SK: 1408 B). */
export function haetaeKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const module = getModule();
  const pkSize = module._haetae_publickeybytes();
  const skSize = module._haetae_secretkeybytes();
  const pkPtr = module._malloc(pkSize);
  const skPtr = module._malloc(skSize);
  try {
    const ret = module._haetae_keypair(pkPtr, skPtr);
    if (ret !== 0) throw new Error(`HAETAE keygen failed (ret=${ret})`);
    return {
      publicKey: new Uint8Array(module.HEAPU8.buffer as ArrayBuffer, pkPtr, pkSize).slice(),
      secretKey: new Uint8Array(module.HEAPU8.buffer as ArrayBuffer, skPtr, skSize).slice(),
    };
  } finally {
    module._free(pkPtr);
    clearAllocation(module, skPtr, skSize);
    module._free(skPtr);
  }
}

/**
 * Sign a message with HAETAE Mode 2.
 * Returns the actual signature bytes (up to 1474 B).
 */
export function haetaeSign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  const module = getModule();
  const expectedSkSize = module._haetae_secretkeybytes();
  if (secretKey.length !== expectedSkSize) {
    throw new Error(`Invalid HAETAE secret key length: ${secretKey.length} (expected ${expectedSkSize})`);
  }
  const maxSigSize = module._haetae_sigbytes();
  const msgPtr = module._malloc(message.length);
  const skPtr = module._malloc(secretKey.length);
  const sigPtr = module._malloc(maxSigSize);
  // size_t (4 bytes in wasm32) to hold the actual signature length
  const siglenPtr = module._malloc(8);
  try {
    module.HEAPU8.set(message, msgPtr);
    module.HEAPU8.set(secretKey, skPtr);
    const ret = module._haetae_sign(sigPtr, siglenPtr, msgPtr, message.length, skPtr);
    if (ret !== 0) throw new Error(`HAETAE sign failed (ret=${ret})`);
    // Read actual length as a 32-bit value (wasm32 size_t)
    const siglen = module.HEAPU32[siglenPtr >> 2];
    if (siglen === 0 || siglen > maxSigSize) {
      throw new Error(`HAETAE returned invalid signature length ${siglen}`);
    }
    return new Uint8Array(module.HEAPU8.buffer as ArrayBuffer, sigPtr, siglen).slice();
  } finally {
    module._free(msgPtr);
    clearAllocation(module, skPtr, secretKey.length);
    module._free(skPtr);
    module._free(sigPtr);
    module._free(siglenPtr);
  }
}

/**
 * Verify a HAETAE Mode 2 signature.
 * Returns true if valid, false if invalid or tampered.
 */
export function haetaeVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  const module = getModule();
  const expectedPkSize = module._haetae_publickeybytes();
  const maxSigSize = module._haetae_sigbytes();
  if (publicKey.length !== expectedPkSize || signature.length === 0 || signature.length > maxSigSize) {
    return false;
  }
  const sigPtr = module._malloc(signature.length);
  const msgPtr = module._malloc(message.length);
  const pkPtr = module._malloc(publicKey.length);
  try {
    module.HEAPU8.set(signature, sigPtr);
    module.HEAPU8.set(message, msgPtr);
    module.HEAPU8.set(publicKey, pkPtr);
    const ret = module._haetae_verify(sigPtr, signature.length, msgPtr, message.length, pkPtr);
    return ret === 0;
  } finally {
    module._free(sigPtr);
    module._free(msgPtr);
    module._free(pkPtr);
  }
}
