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
import { encode, decode, toBase64 } from './utils';

export type { WrappedShare };

export interface SealedBox {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  wrappedShares: WrappedShare[]; // always 3 elements — one per keyholder
  signature: Uint8Array;         // HAETAE Mode 2 signature
  sigPublicKey: Uint8Array;      // HAETAE public key (992 B) — needed for verify
  createdAt: string;
}

// Optional visualization payload captured during a seal — REAL bytes (the actual
// AES key and the actual 3 Shamir shares) used only to drive the on-screen
// key-strip split animation, then discarded by the caller. Never fabricated.
export interface SealVisual {
  /** The random 32-byte AES-256 key that was split (before zeroization). */
  key: Uint8Array;
  /** The 3 real Shamir shares of that key — one per keyholder. */
  shares: [Uint8Array, Uint8Array, Uint8Array];
}

export interface SealOutcome {
  box: SealedBox;
  visual: SealVisual;
}

// Optional visualization payload — REAL cryptographic bytes captured during an
// open, used only to drive the on-screen Shamir key-strip animation. These are
// genuine outputs (the actual reconstructed key, the actual per-slot unwrap
// outcome), never fabricated: on a below-threshold open the `reconstructedKey`
// is the mathematically-wrong Lagrange result, exactly as the reveal shows.
export interface OpenVisual {
  /** Which of the 3 password slots yielded a valid Shamir share (real unwrap outcome). */
  shareStatus: [boolean, boolean, boolean];
  /** Whether the container's HAETAE signature verified (integrity gate). */
  signatureValid: boolean;
  /** The bytes Lagrange interpolation produced — the true AES key iff >= 2 valid shares. */
  reconstructedKey: Uint8Array | null;
}

export type OpenResult =
  | { success: true; message: string; validShareCount: number; visual: OpenVisual }
  | { success: false; gibberish: Uint8Array; validShareCount: number; visual: OpenVisual };

// -- Container data corpus for signing --
//
// Serialised as canonical JSON with keys sorted alphabetically at every level.
// Byte arrays are base64-encoded so field names act as delimiters — the
// encoding is injective and matches the Rust core spec §6.2.
// The `signature` field is intentionally excluded.
//
// sigPublicKey and createdAt are included so the signature binds its own
// verification key and timestamp and cannot be transplanted to another container.
function buildContainerData(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  wrappedShares: WrappedShare[],
  sigPublicKey: Uint8Array,
  createdAt: string,
): Uint8Array {
  // Keys at every level are in strict alphabetical order so that any
  // compliant JSON serialiser produces the same byte string.
  const corpus = {
    ciphertext: toBase64(ciphertext),
    createdAt,
    nonce: toBase64(nonce),
    sigPublicKey: toBase64(sigPublicKey),
    wrappedShares: wrappedShares.map(ws => ({
      iterations: ws.iterations,
      kemCiphertext: toBase64(ws.kemCiphertext),
      publicKey: toBase64(ws.publicKey),
      salt: toBase64(ws.salt),
      shareNonce: toBase64(ws.shareNonce),
      skNonce: toBase64(ws.skNonce),
      wrappedSecretKey: toBase64(ws.wrappedSecretKey),
      wrappedShare: toBase64(ws.wrappedShare),
    })),
  };
  return encode(JSON.stringify(corpus));
}

// -- Seal core: encrypt message, split key, wrap shares, sign container --
// Also captures the real AES key + 3 Shamir shares so callers that want the
// on-screen "key splits into 3 pieces" animation can show genuine bytes. The
// visual copies are the caller's responsibility to zeroize after rendering.
async function sealMessageCore(
  message: string,
  passwords: [string, string, string],
): Promise<SealOutcome> {
  // Step 1 — AES-256-GCM: encrypt the plaintext message
  const key = await generateAesKey();
  const rawKey = await exportRawKey(key);
  const plaintext = encode(message);
  const { ciphertext, nonce } = await aesEncrypt(plaintext, key);

  // Snapshot the real key for the split animation before it is zeroized below.
  const keySnapshot = rawKey.slice();

  // Step 2 — Shamir split: split the 32-byte AES key into 3 shares, threshold 2
  const shares: Share[] = splitSecret(rawKey, 2, 3);
  rawKey.fill(0);

  // Snapshot the 3 real shares for the split animation before zeroization.
  const shareSnapshots: [Uint8Array, Uint8Array, Uint8Array] = [
    shares[0].data.slice(),
    shares[1].data.slice(),
    shares[2].data.slice(),
  ];

  // Step 3 — SMAUG-T wrap: for each participant —
  //   fresh SMAUG-T keypair → encapsulate → AES-GCM wrap share;
  //   PBKDF2(password) → AES-GCM encrypt SMAUG-T secret key
  const wrappedShares = await Promise.all(
    shares.map((share, i) => wrapShare(share.data, passwords[i])),
  );
  // Zeroize Shamir share data — sensitive key material, no longer needed.
  for (const share of shares) share.data.fill(0);

  // Step 4 — HAETAE sign: sign the full container including sigPublicKey + createdAt
  // Generate keypair first so sigPublicKey can be included in the signed corpus.
  const createdAt = new Date().toISOString();
  const { publicKey: sigPublicKey, secretKey: sigSecretKey } = haetaeKeypair();
  const containerData = buildContainerData(ciphertext, nonce, wrappedShares, sigPublicKey, createdAt);
  const signature = haetaeSign(containerData, sigSecretKey);
  sigSecretKey.fill(0);

  return {
    box: { ciphertext, nonce, wrappedShares, signature, sigPublicKey, createdAt },
    visual: { key: keySnapshot, shares: shareSnapshots },
  };
}

// -- Seal: encrypt message, split key, wrap shares, sign container --
// Convenience wrapper for callers that do not need the visualization payload
// (demo generation, tests); the captured key/share snapshots are zeroized here.
export async function sealMessage(
  message: string,
  passwords: [string, string, string],
): Promise<SealedBox> {
  const { box, visual } = await sealMessageCore(message, passwords);
  visual.key.fill(0);
  for (const s of visual.shares) s.fill(0);
  return box;
}

/** Seal + return the real key/share bytes for the on-screen split animation. */
export async function sealMessageWithVisual(
  message: string,
  passwords: [string, string, string],
): Promise<SealOutcome> {
  return sealMessageCore(message, passwords);
}

// -- Open: verify, unwrap shares, reconstruct key, decrypt --
export async function openBox(
  box: SealedBox,
  passwords: [string | null, string | null, string | null],
): Promise<OpenResult> {
  // Step 1 — HAETAE verify: reject tampered containers outright
  const containerData = buildContainerData(box.ciphertext, box.nonce, box.wrappedShares, box.sigPublicKey, box.createdAt);
  const valid = haetaeVerify(box.signature, containerData, box.sigPublicKey);
  if (!valid) {
    const garbage = crypto.getRandomValues(new Uint8Array(Math.max(8, box.ciphertext.length - 16)));
    return {
      success: false,
      gibberish: garbage,
      validShareCount: 0,
      // Integrity failure: signature did not verify. No share was even attempted.
      visual: { shareStatus: [false, false, false], signatureValid: false, reconstructedKey: null },
    };
  }

  const validShares: Share[] = [];
  let validShareCount = 0;
  const shareStatus: [boolean, boolean, boolean] = [false, false, false];

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
      shareStatus[i] = true;
    } catch {
      // Wrong password: AES-GCM auth tag mismatch → DOMException
    }
  }

  if (validShares.length === 0) {
    const garbage = crypto.getRandomValues(
      new Uint8Array(Math.max(8, box.ciphertext.length - 16)),
    );
    return {
      success: false,
      gibberish: garbage,
      validShareCount: 0,
      visual: { shareStatus, signatureValid: true, reconstructedKey: null },
    };
  }

  // Step 3 — Shamir reconstruct: correct only if validShares.length >= threshold (2)
  const reconstructedKey = reconstructSecret(validShares);
  // Snapshot the *real* Lagrange output for the on-screen key-strip animation
  // BEFORE zeroization. With >= 2 shares this equals the true AES key; with 1
  // share it is the genuinely-wrong reconstruction (unrelated bytes) — never faked.
  const keySnapshot = reconstructedKey.slice();
  // Zeroize share data — sensitive key material, no longer needed after reconstruction.
  for (const share of validShares) share.data.fill(0);

  // Step 4 — AES-256-GCM decrypt: auth tag fails if the key is wrong (< 2 shares)
  try {
    const cryptoKey = await importRawKey(reconstructedKey);
    const plaintext = await aesDecrypt(box.ciphertext, box.nonce, cryptoKey);
    reconstructedKey.fill(0);
    return {
      success: true,
      message: decode(plaintext),
      validShareCount,
      visual: { shareStatus, signatureValid: true, reconstructedKey: keySnapshot },
    };
  } catch {
    reconstructedKey.fill(0);
    // Use random bytes for the failure animation — never derive from share material.
    const gibberish = crypto.getRandomValues(
      new Uint8Array(Math.max(8, box.ciphertext.length - 16)),
    );
    return {
      success: false,
      gibberish,
      validShareCount,
      visual: { shareStatus, signatureValid: true, reconstructedKey: keySnapshot },
    };
  }
}
