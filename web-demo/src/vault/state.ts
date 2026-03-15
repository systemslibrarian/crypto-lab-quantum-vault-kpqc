// Vault state: types, localStorage persistence, serialization helpers

import { toBase64, fromBase64 } from '../crypto/utils';
import type { SealedBox, WrappedShare } from '../crypto/pipeline';

// SMAUG-T Level 1 / HAETAE Mode 2 expected byte lengths
const EXPECTED = {
  nonce:          12,
  salt:           16,
  kemCiphertext:  672,
  shareNonce:     12,
  publicKey:      672,
  skNonce:        12,
  sigPublicKey:   992,
  maxSignature:   1474,
  maxCiphertext:  64 * 1024 * 1024, // 64 MiB
} as const;

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
  boxes: Record<string, VaultBox>; // keys: "01" – "12"
  version: number;                 // format version, currently 2
}

const STORAGE_KEY = 'quantum-vault-data';

export function loadVaultState(): VaultState | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as unknown;
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      'boxes' in parsed &&
      'version' in parsed &&
      (parsed as VaultState).version === 2
    ) {
      return parsed as VaultState;
    }
    return null;
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
  if (!Array.isArray(vb.wrappedShares) || vb.wrappedShares.length !== 3) {
    throw new Error('Invalid container: wrappedShares must have exactly 3 elements');
  }

  const ciphertext    = fromBase64(vb.ciphertext);
  const nonce         = fromBase64(vb.nonce);
  const signature     = fromBase64(vb.signature);
  const sigPublicKey  = fromBase64(vb.sigPublicKey);

  assertMaxLen(ciphertext,   EXPECTED.maxCiphertext, 'ciphertext');
  assertLen(nonce,           EXPECTED.nonce,         'nonce');
  assertLen(sigPublicKey,    EXPECTED.sigPublicKey,  'sigPublicKey');
  assertMaxLen(signature,    EXPECTED.maxSignature,  'signature');

  const wrappedShares = vb.wrappedShares.map((ws, i) => {
    const salt             = fromBase64(ws.salt);
    const kemCiphertext    = fromBase64(ws.kemCiphertext);
    const wrappedShare     = fromBase64(ws.wrappedShare);
    const shareNonce       = fromBase64(ws.shareNonce);
    const publicKey        = fromBase64(ws.publicKey);
    const wrappedSecretKey = fromBase64(ws.wrappedSecretKey);
    const skNonce          = fromBase64(ws.skNonce);

    assertLen(salt,          EXPECTED.salt,          `wrappedShares[${i}].salt`);
    assertLen(kemCiphertext, EXPECTED.kemCiphertext, `wrappedShares[${i}].kemCiphertext`);
    assertLen(shareNonce,    EXPECTED.shareNonce,    `wrappedShares[${i}].shareNonce`);
    assertLen(publicKey,     EXPECTED.publicKey,     `wrappedShares[${i}].publicKey`);
    assertLen(skNonce,       EXPECTED.skNonce,       `wrappedShares[${i}].skNonce`);

    return {
      salt,
      kemCiphertext,
      wrappedShare,
      shareNonce,
      publicKey,
      wrappedSecretKey,
      skNonce,
      iterations: ws.iterations ?? 100_000,
    };
  });

  return { ciphertext, nonce, wrappedShares, signature, sigPublicKey, createdAt: vb.createdAt };
}
