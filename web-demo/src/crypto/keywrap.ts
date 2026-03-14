// Real SMAUG-T (KpqC standard) key encapsulation for Shamir share wrapping.
//
// Deposit flow for each participant:
//   1. Generate a fresh SMAUG-T keypair
//   2. Encapsulate → ciphertext + sharedSecret (32 B)
//   3. AES-GCM encrypt the Shamir share using sharedSecret
//   4. Derive a "password seal" from the password via PBKDF2 → AES-GCM
//   5. Encrypt the SMAUG-T secret key with the password seal
//   Store: { salt, kemCiphertext, wrappedShare, shareNonce, publicKey, wrappedSecretKey, skNonce }
//
// Retrieval flow:
//   1. PBKDF2-derive password seal from stored salt
//   2. Decrypt wrappedSecretKey → SMAUG-T secret key  (wrong pw → DOMException)
//   3. smaugDecapsulate(kemCiphertext, secretKey) → sharedSecret
//   4. AES-GCM decrypt wrappedShare using sharedSecret → Shamir share bytes

import { smaugKeypair, smaugEncapsulate, smaugDecapsulate } from './smaug';
import { buf } from './utils';

export interface WrappedShare {
  salt: Uint8Array;             // 16-byte PBKDF2 salt
  kemCiphertext: Uint8Array;    // SMAUG-T KEM ciphertext (672 B)
  wrappedShare: Uint8Array;     // AES-GCM encrypted Shamir share
  shareNonce: Uint8Array;       // 12-byte AES-GCM nonce for share
  publicKey: Uint8Array;        // SMAUG-T public key (672 B) — stored for reference
  wrappedSecretKey: Uint8Array; // AES-GCM encrypted SMAUG-T secret key
  skNonce: Uint8Array;          // 12-byte AES-GCM nonce for SK encryption
}

/** Derive a 256-bit AES key from a password using PBKDF2-SHA-256. */
async function derivePasswordKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const pwKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: buf(salt), iterations: 100_000, hash: 'SHA-256' },
    pwKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Import 32 raw bytes as an AES-256-GCM key for share wrapping. */
async function importSharedSecretAsKey(ss: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    buf(ss),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function wrapShare(
  shareData: Uint8Array,
  password: string,
): Promise<WrappedShare> {
  // 1. Generate a fresh SMAUG-T keypair for this share
  const { publicKey, secretKey } = smaugKeypair();

  // 2. Encapsulate against the public key → KEM ciphertext + shared secret
  const { ciphertext: kemCiphertext, sharedSecret } = smaugEncapsulate(publicKey);

  // 3. AES-GCM encrypt the Shamir share using the KEM shared secret
  const shareWrapKey = await importSharedSecretAsKey(sharedSecret);
  const shareNonce = crypto.getRandomValues(new Uint8Array(12));
  const wrappedShareBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: buf(shareNonce) }, shareWrapKey, buf(shareData),
  );
  const wrappedShare = new Uint8Array(wrappedShareBuf);

  // 4. Encrypt the SMAUG-T secret key with the password-derived AES key
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const passwordKey = await derivePasswordKey(password, salt);
  const skNonce = crypto.getRandomValues(new Uint8Array(12));
  const wrappedSKBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: buf(skNonce) }, passwordKey, buf(secretKey),
  );
  const wrappedSecretKey = new Uint8Array(wrappedSKBuf);

  return { salt, kemCiphertext, wrappedShare, shareNonce, publicKey, wrappedSecretKey, skNonce };
}

export async function unwrapShare(
  wrapped: WrappedShare,
  password: string,
): Promise<Uint8Array> {
  // 1. Re-derive the password seal
  const passwordKey = await derivePasswordKey(password, wrapped.salt);

  // 2. Decrypt the SMAUG-T secret key — wrong password → DOMException (caught in pipeline)
  const skBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: buf(wrapped.skNonce) }, passwordKey, buf(wrapped.wrappedSecretKey),
  );
  const secretKey = new Uint8Array(skBuf);

  // 3. SMAUG-T decapsulate → recover the KEM shared secret
  const sharedSecret = smaugDecapsulate(wrapped.kemCiphertext, secretKey);

  // 4. AES-GCM decrypt the Shamir share using the recovered shared secret
  const shareWrapKey = await importSharedSecretAsKey(sharedSecret);
  const shareBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: buf(wrapped.shareNonce) }, shareWrapKey, buf(wrapped.wrappedShare),
  );
  return new Uint8Array(shareBytes);
}
