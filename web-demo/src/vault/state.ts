// Vault state: types, localStorage persistence, serialization helpers

import { toBase64, fromBase64 } from '../crypto/utils';
import type { SealedBox, WrappedShare } from '../crypto/pipeline';

// SMAUG-T Level 1 / HAETAE Mode 2 expected byte lengths
const EXPECTED = {
  nonce:          12,
  salt:           16,
  kemCiphertext:  672,
  wrappedShare:   48,  // 32-byte Shamir share + 16-byte AES-GCM tag
  shareNonce:     12,
  publicKey:      672,
  wrappedSecretKey: 848, // 832-byte SMAUG-T secret key + 16-byte AES-GCM tag
  skNonce:        12,
  sigPublicKey:   992,
  maxSignature:   1474,
  maxCiphertext:  64 * 1024 * 1024, // 64 MiB
} as const;

const MIN_PBKDF2_ITERATIONS = 100_000;
const MAX_PBKDF2_ITERATIONS = 1_000_000;

function assertLen(arr: Uint8Array, expected: number, field: string): void {
  if (arr.length !== expected) {
    throw new Error(`Invalid container: field "${field}" must be ${expected} bytes, got ${arr.length}`);
  }
}

function assertMaxLen(arr: Uint8Array, max: number, field: string): void {
  if (arr.length === 0 || arr.length > max) {
    throw new Error(`Invalid container: field "${field}" length ${arr.length} is out of range [1, ${max}]`);
  }
}

function decodeBase64Field(value: unknown, field: string): Uint8Array {
  if (typeof value !== 'string') {
    throw new Error(`Invalid container: field "${field}" must be base64 text`);
  }
  try {
    return fromBase64(value);
  } catch {
    throw new Error(`Invalid container: field "${field}" must be valid base64`);
  }
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function assertIterations(value: unknown, field: string): number {
  const iterations = value ?? MIN_PBKDF2_ITERATIONS;
  if (
    !Number.isSafeInteger(iterations) ||
    (iterations as number) < MIN_PBKDF2_ITERATIONS ||
    (iterations as number) > MAX_PBKDF2_ITERATIONS
  ) {
    throw new Error(
      `Invalid container: field "${field}" must be an integer from ${MIN_PBKDF2_ITERATIONS} to ${MAX_PBKDF2_ITERATIONS}`,
    );
  }
  return iterations as number;
}

export interface WrappedShareSerialized {
  salt: string;             // base64 (16 bytes)
  kemCiphertext: string;    // base64 (672 bytes)
  wrappedShare: string;     // base64
  shareNonce: string;       // base64 (12 bytes)
  publicKey: string;        // base64 (672 bytes)
  wrappedSecretKey: string; // base64
  skNonce: string;          // base64 (12 bytes)
  iterations?: number;      // PBKDF2 iteration count; absent in v2 containers (defaults to 100_000)
}

export interface VaultBox {
  ciphertext: string;                       // base64
  nonce: string;                            // base64 (12 bytes)
  wrappedShares: WrappedShareSerialized[];  // always 3 elements
  signature: string;                        // base64 (HAETAE Mode 2)
  sigPublicKey: string;                     // base64 (992 bytes)
  createdAt: string;                        // ISO timestamp
}

export interface VaultState {
  boxes: Record<string, VaultBox>; // keys: "01" – "09"
  version: number;                 // format version, currently 2
}

const STORAGE_KEY = 'quantum-vault-data';

/** Validate untrusted parsed state without trusting its TypeScript shape. */
export function validateVaultState(value: unknown): VaultState | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  const candidate = value as Record<string, unknown>;
  if (
    candidate.version !== 2 ||
    typeof candidate.boxes !== 'object' ||
    candidate.boxes === null ||
    Array.isArray(candidate.boxes)
  ) {
    return null;
  }

  const entries = Object.entries(candidate.boxes as Record<string, unknown>);
  if (entries.length > 9) return null;

  const boxes: Record<string, VaultBox> = {};
  try {
    for (const [key, rawBox] of entries) {
      if (!/^0[1-9]$/.test(key)) return null;
      deserializeSealedBox(rawBox as VaultBox);
      boxes[key] = rawBox as VaultBox;
    }
  } catch {
    return null;
  }

  return { boxes, version: 2 };
}

export function loadVaultState(): VaultState | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as unknown;
    return validateVaultState(parsed);
  } catch {
    return null;
  }
}

export function saveVaultState(state: VaultState): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

export function clearVaultState(): void {
  localStorage.removeItem(STORAGE_KEY);
}

export function emptyVaultState(): VaultState {
  return { boxes: {}, version: 2 };
}

export function serializeSealedBox(box: SealedBox): VaultBox {
  return {
    ciphertext: toBase64(box.ciphertext),
    nonce: toBase64(box.nonce),
    wrappedShares: box.wrappedShares.map((ws: WrappedShare) => ({
      salt: toBase64(ws.salt),
      kemCiphertext: toBase64(ws.kemCiphertext),
      wrappedShare: toBase64(ws.wrappedShare),
      shareNonce: toBase64(ws.shareNonce),
      publicKey: toBase64(ws.publicKey),
      wrappedSecretKey: toBase64(ws.wrappedSecretKey),
      skNonce: toBase64(ws.skNonce),
      iterations: ws.iterations,
    })),
    signature: toBase64(box.signature),
    sigPublicKey: toBase64(box.sigPublicKey),
    createdAt: box.createdAt,
  };
}

export function deserializeSealedBox(vb: VaultBox): SealedBox {
  if (typeof vb !== 'object' || vb === null) {
    throw new Error('Invalid container: box must be an object');
  }
  if (!Array.isArray(vb.wrappedShares) || vb.wrappedShares.length !== 3) {
    throw new Error('Invalid container: wrappedShares must have exactly 3 elements');
  }

  const ciphertext    = decodeBase64Field(vb.ciphertext, 'ciphertext');
  const nonce         = decodeBase64Field(vb.nonce, 'nonce');
  const signature     = decodeBase64Field(vb.signature, 'signature');
  const sigPublicKey  = decodeBase64Field(vb.sigPublicKey, 'sigPublicKey');

  assertMaxLen(ciphertext,   EXPECTED.maxCiphertext, 'ciphertext');
  assertLen(nonce,           EXPECTED.nonce,         'nonce');
  assertLen(sigPublicKey,    EXPECTED.sigPublicKey,  'sigPublicKey');
  assertMaxLen(signature,    EXPECTED.maxSignature,  'signature');
  if (!isCanonicalTimestamp(vb.createdAt)) {
    throw new Error('Invalid container: createdAt must be a canonical ISO timestamp');
  }

  const wrappedShares = vb.wrappedShares.map((ws, i) => {
    if (typeof ws !== 'object' || ws === null || Array.isArray(ws)) {
      throw new Error(`Invalid container: wrappedShares[${i}] must be an object`);
    }
    const salt             = decodeBase64Field(ws.salt, `wrappedShares[${i}].salt`);
    const kemCiphertext    = decodeBase64Field(ws.kemCiphertext, `wrappedShares[${i}].kemCiphertext`);
    const wrappedShare     = decodeBase64Field(ws.wrappedShare, `wrappedShares[${i}].wrappedShare`);
    const shareNonce       = decodeBase64Field(ws.shareNonce, `wrappedShares[${i}].shareNonce`);
    const publicKey        = decodeBase64Field(ws.publicKey, `wrappedShares[${i}].publicKey`);
    const wrappedSecretKey = decodeBase64Field(ws.wrappedSecretKey, `wrappedShares[${i}].wrappedSecretKey`);
    const skNonce          = decodeBase64Field(ws.skNonce, `wrappedShares[${i}].skNonce`);

    assertLen(salt,          EXPECTED.salt,          `wrappedShares[${i}].salt`);
    assertLen(kemCiphertext, EXPECTED.kemCiphertext, `wrappedShares[${i}].kemCiphertext`);
    assertLen(wrappedShare,  EXPECTED.wrappedShare,  `wrappedShares[${i}].wrappedShare`);
    assertLen(shareNonce,    EXPECTED.shareNonce,    `wrappedShares[${i}].shareNonce`);
    assertLen(publicKey,     EXPECTED.publicKey,     `wrappedShares[${i}].publicKey`);
    assertLen(wrappedSecretKey, EXPECTED.wrappedSecretKey, `wrappedShares[${i}].wrappedSecretKey`);
    assertLen(skNonce,       EXPECTED.skNonce,       `wrappedShares[${i}].skNonce`);

    return {
      salt,
      kemCiphertext,
      wrappedShare,
      shareNonce,
      publicKey,
      wrappedSecretKey,
      skNonce,
      iterations: assertIterations(ws.iterations, `wrappedShares[${i}].iterations`),
    };
  });

  return { ciphertext, nonce, wrappedShares, signature, sigPublicKey, createdAt: vb.createdAt };
}
