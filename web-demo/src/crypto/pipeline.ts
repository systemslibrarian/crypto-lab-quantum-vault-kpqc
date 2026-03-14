// Full cryptographic pipeline: seal (encrypt) and open (decrypt) — v5.0 (real KpqC)
//
// Seal pipeline:
//   AES-256-GCM  →  Shamir split  →  SMAUG-T wrap  →  HAETAE sign
//
// Open pipeline:
//   HAETAE verify  →  SMAUG-T unlock  →  Shamir reconstruct  →  AES-256-GCM
//
// SMAUG-T Level 1 (KEM) and HAETAE Mode 2 (signature) are both genuine KpqC
// WASM modules — no mocks or HMAC substitutes.
//
// NOTE: The pipeline functions are pure crypto — no animation delays.
// Animation is driven separately in ui/pipeline-ui.ts.

import { generateAesKey, exportRawKey, importRawKey, aesEncrypt, aesDecrypt } from './aes';
import { splitSecret, reconstructSecret } from './shamir';
import type { Share } from './shamir';
import { wrapShare, unwrapShare } from './keywrap';
import type { WrappedShare } from './keywrap';
import { haetaeKeypair, haetaeSign, haetaeVerify } from './haetae';
import { encode, decode, concatBytes } from './utils';

export type { WrappedShare };

export interface SealedBox {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  wrappedShares: WrappedShare[]; // always 3 elements — one per keyholder
  signature: Uint8Array;         // HAETAE Mode 2 signature
  sigPublicKey: Uint8Array;      // HAETAE public key (992 B) — needed for verify
  createdAt: string;
}

export type OpenResult =
  | { success: true; message: string; validShareCount: number }
  | { success: false; gibberish: Uint8Array; validShareCount: number };

// -- Container data corpus for signing (everything except the signature itself) --
function buildContainerData(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  wrappedShares: WrappedShare[],
): Uint8Array {
  const parts: Uint8Array[] = [nonce, ciphertext];
  for (const ws of wrappedShares) {
    parts.push(
      ws.salt,
      ws.kemCiphertext,
      ws.wrappedShare,
      ws.shareNonce,
      ws.publicKey,
      ws.wrappedSecretKey,
      ws.skNonce,
    );
  }
  return concatBytes(...parts);
}

// -- Seal: encrypt message, split key, wrap shares, sign container --
export async function sealMessage(
  message: string,
  passwords: [string, string, string],
): Promise<SealedBox> {
  // Step 1 — AES-256-GCM: encrypt the plaintext message
  const key = await generateAesKey();
  const rawKey = await exportRawKey(key);
  const plaintext = encode(message);
  const { ciphertext, nonce } = await aesEncrypt(plaintext, key);

  // Step 2 — Shamir split: split the 32-byte AES key into 3 shares, threshold 2
  const shares: Share[] = splitSecret(rawKey, 2, 3);

  // Step 3 — SMAUG-T wrap: for each participant —
  //   fresh SMAUG-T keypair → encapsulate → AES-GCM wrap share;
  //   PBKDF2(password) → AES-GCM encrypt SMAUG-T secret key
  const wrappedShares = await Promise.all(
    shares.map((share, i) => wrapShare(share.data, passwords[i])),
  );

  // Step 4 — HAETAE sign: sign the full container serialization
  const containerData = buildContainerData(ciphertext, nonce, wrappedShares);
  const { publicKey: sigPublicKey, secretKey: sigSecretKey } = haetaeKeypair();
  const signature = haetaeSign(containerData, sigSecretKey);

  return {
    ciphertext,
    nonce,
    wrappedShares,
    signature,
    sigPublicKey,
    createdAt: new Date().toISOString(),
  };
}

// -- Open: verify, unwrap shares, reconstruct key, decrypt --
export async function openBox(
  box: SealedBox,
  passwords: [string | null, string | null, string | null],
): Promise<OpenResult> {
  // Step 1 — HAETAE verify: reject tampered containers outright
  const containerData = buildContainerData(box.ciphertext, box.nonce, box.wrappedShares);
  const valid = haetaeVerify(box.signature, containerData, box.sigPublicKey);
  if (!valid) {
    const garbage = crypto.getRandomValues(new Uint8Array(Math.max(8, box.ciphertext.length - 16)));
    return { success: false, gibberish: garbage, validShareCount: 0 };
  }

  const validShares: Share[] = [];
  let validShareCount = 0;

  // Step 2 — SMAUG-T unlock: for each non-empty password —
  //   PBKDF2(password) → decrypt SMAUG-T SK → decapsulate → AES-GCM decrypt share
  //   Wrong password → decrypt SK throws DOMException → share unavailable
  for (let i = 0; i < 3; i++) {
    const pw = passwords[i];
    if (!pw) continue;
    try {
      const shareData = await unwrapShare(box.wrappedShares[i], pw);
      validShares.push({ index: i + 1, data: shareData });
      validShareCount++;
    } catch {
      // Wrong password: AES-GCM auth tag mismatch → DOMException
    }
  }

  if (validShares.length === 0) {
    const garbage = crypto.getRandomValues(
      new Uint8Array(Math.max(8, box.ciphertext.length - 16)),
    );
    return { success: false, gibberish: garbage, validShareCount: 0 };
  }

  // Step 3 — Shamir reconstruct: correct only if validShares.length >= threshold (2)
  const reconstructedKey = reconstructSecret(validShares);

  // Step 4 — AES-256-GCM decrypt: auth tag fails if the key is wrong (< 2 shares)
  try {
    const cryptoKey = await importRawKey(reconstructedKey);
    const plaintext = await aesDecrypt(box.ciphertext, box.nonce, cryptoKey);
    return { success: true, message: decode(plaintext), validShareCount };
  } catch {
    const gibberish = new Uint8Array(Math.max(8, box.ciphertext.length - 16));
    for (let i = 0; i < gibberish.length; i++) {
      gibberish[i] = reconstructedKey[i % reconstructedKey.length] ^ ((i * 7 + 31) & 0xff);
    }
    return { success: false, gibberish, validShareCount };
  }
}
