// SPDX-License-Identifier: MIT
/**
 * TypeScript type definitions for Emscripten-generated WASM modules.
 * These interfaces replace the use of `any` for better type safety.
 */

/**
 * Base interface for all Emscripten modules.
 * Contains common memory management functions.
 */
export interface EmscriptenModuleBase {
  /** Allocate `size` bytes on the WASM heap, returns pointer. */
  _malloc(size: number): number;
  /** Free memory at pointer `ptr`. */
  _free(ptr: number): void;
  /** Direct view of WASM linear memory as unsigned 8-bit integers. */
  HEAPU8: Uint8Array;
  /** Direct view of WASM linear memory as unsigned 32-bit integers. */
  HEAPU32: Uint32Array;
}

/**
 * SMAUG-T Level 1 KEM module interface.
 * Compiled from the KpqC reference implementation.
 */
export interface SmaugModule extends EmscriptenModuleBase {
  /** Returns public key size in bytes (672). */
  _smaug_publickeybytes(): number;
  /** Returns secret key size in bytes (832). */
  _smaug_secretkeybytes(): number;
  /** Returns ciphertext size in bytes (672). */
  _smaug_ciphertextbytes(): number;
  /** Returns shared secret size in bytes (32). */
  _smaug_sharedsecretbytes(): number;
  /** Generate keypair: returns 0 on success. */
  _smaug_keypair(pkPtr: number, skPtr: number): number;
  /** Encapsulate: returns 0 on success. */
  _smaug_encapsulate(ctPtr: number, ssPtr: number, pkPtr: number): number;
  /** Decapsulate: returns 0 on success. */
  _smaug_decapsulate(ssPtr: number, ctPtr: number, skPtr: number): number;
  /** Securely zero memory (cannot be optimized away). */
  _smaug_secure_zeroize(ptr: number, size: number): void;
}

/**
 * HAETAE Mode 2 signature module interface.
 * Compiled from the KpqC reference implementation.
 */
export interface HaetaeModule extends EmscriptenModuleBase {
  /** Returns public key size in bytes (992). */
  _haetae_publickeybytes(): number;
  /** Returns secret key size in bytes (1408). */
  _haetae_secretkeybytes(): number;
  /** Returns maximum signature size in bytes (1474). */
  _haetae_sigbytes(): number;
  /** Generate keypair: returns 0 on success. */
  _haetae_keypair(pkPtr: number, skPtr: number): number;
  /** Sign message: writes signature to sigPtr, actual length to siglenPtr. Returns 0 on success. */
  _haetae_sign(
    sigPtr: number,
    siglenPtr: number,
    msgPtr: number,
    msgLen: number,
    skPtr: number
  ): number;
  /** Verify signature: returns 0 on valid signature. */
  _haetae_verify(
    sigPtr: number,
    sigLen: number,
    msgPtr: number,
    msgLen: number,
    pkPtr: number
  ): number;
  /** Securely zero memory (cannot be optimized away). */
  _haetae_secure_zeroize(ptr: number, size: number): void;
}

/**
 * Emscripten module factory options.
 */
export interface EmscriptenModuleOptions {
  /** Function to resolve paths to .wasm files at runtime. */
  locateFile?: (path: string) => string;
}

/**
 * Factory function type for creating Emscripten modules.
 */
export type EmscriptenModuleFactory<T extends EmscriptenModuleBase> = (
  options?: EmscriptenModuleOptions
) => Promise<T>;
