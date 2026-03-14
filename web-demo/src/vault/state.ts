// Vault state: types, localStorage persistence, serialization helpers

import { toBase64, fromBase64 } from '../crypto/utils';
import type { SealedBox, WrappedShare } from '../crypto/pipeline';

export interface WrappedShareSerialized {
  salt: string;             // base64 (16 bytes)
  kemCiphertext: string;    // base64 (672 bytes)
  wrappedShare: string;     // base64
  shareNonce: string;       // base64 (12 bytes)
  publicKey: string;        // base64 (672 bytes)
  wrappedSecretKey: string; // base64
  skNonce: string;          // base64 (12 bytes)
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
    })),
    signature: toBase64(box.signature),
    sigPublicKey: toBase64(box.sigPublicKey),
    createdAt: box.createdAt,
  };
}

export function deserializeSealedBox(vb: VaultBox): SealedBox {
  return {
    ciphertext: fromBase64(vb.ciphertext),
    nonce: fromBase64(vb.nonce),
    wrappedShares: vb.wrappedShares.map(ws => ({
      salt: fromBase64(ws.salt),
      kemCiphertext: fromBase64(ws.kemCiphertext),
      wrappedShare: fromBase64(ws.wrappedShare),
      shareNonce: fromBase64(ws.shareNonce),
      publicKey: fromBase64(ws.publicKey),
      wrappedSecretKey: fromBase64(ws.wrappedSecretKey),
      skNonce: fromBase64(ws.skNonce),
    })),
    signature: fromBase64(vb.signature),
    sigPublicKey: fromBase64(vb.sigPublicKey),
    createdAt: vb.createdAt,
  };
}
