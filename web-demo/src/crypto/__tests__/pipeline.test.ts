/**
 * Pipeline integration tests — sealMessage / openBox.
 *
 * SMAUG-T and HAETAE WASM modules are mocked with lightweight deterministic
 * replacements so these tests run in Node without any .wasm files.  All other
 * crypto (AES-256-GCM, PBKDF2, Shamir SSS) runs against the real Web Crypto
 * API, providing meaningful end-to-end coverage.
 *
 * Mock KEM design (XOR-based round-trip):
 *   keypair : sk = 32 random bytes; pk = sk XOR 0xAB
 *   encaps  : ss = 32 random bytes; ct = ss XOR pk
 *   decaps  : pk' = sk XOR 0xAB; ss = ct XOR pk'  → recovers original ss ✓
 *
 * Mock signature design (deterministic MAC):
 *   keypair : sk = 32 random bytes; pk = sk XOR 0xCD
 *   sign    : sig[i] = (sk[i%32] ^ msg[i%msg.len] ^ (i*7)) & 0xFF
 *   verify  : sk' = pk XOR 0xCD; recompute sig and compare byte-by-byte ✓
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { MockedFunction } from 'vitest';

// ---- Mock SMAUG-T ----
vi.mock('../smaug', () => ({
  initSmaug: vi.fn().mockResolvedValue(undefined),

  smaugKeypair: (): { publicKey: Uint8Array; secretKey: Uint8Array } => {
    const sk = crypto.getRandomValues(new Uint8Array(32));
    const pk = new Uint8Array(sk.map(b => (b ^ 0xab) & 0xff));
    return { publicKey: pk, secretKey: sk };
  },

  smaugEncapsulate: (
    pk: Uint8Array,
  ): { ciphertext: Uint8Array; sharedSecret: Uint8Array } => {
    const ss = crypto.getRandomValues(new Uint8Array(32));
    const ct = new Uint8Array(ss.map((b, i) => (b ^ pk[i % pk.length]) & 0xff));
    return { ciphertext: ct, sharedSecret: ss };
  },

  smaugDecapsulate: (ct: Uint8Array, sk: Uint8Array): Uint8Array => {
    const pk = new Uint8Array(sk.map(b => (b ^ 0xab) & 0xff));
    return new Uint8Array(ct.map((b, i) => (b ^ pk[i % pk.length]) & 0xff));
  },
}));

// ---- Mock HAETAE ----
vi.mock('../haetae', () => ({
  initHaetae: vi.fn().mockResolvedValue(undefined),

  haetaeKeypair: (): { publicKey: Uint8Array; secretKey: Uint8Array } => {
    const sk = crypto.getRandomValues(new Uint8Array(32));
    const pk = new Uint8Array(sk.map(b => (b ^ 0xcd) & 0xff));
    return { publicKey: pk, secretKey: sk };
  },

  haetaeSign: (msg: Uint8Array, sk: Uint8Array): Uint8Array => {
    const sig = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      sig[i] = (sk[i % sk.length] ^ msg[i % msg.length] ^ (i * 7)) & 0xff;
    }
    return sig;
  },

  haetaeVerify: (sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean => {
    const sk = new Uint8Array(pk.map(b => (b ^ 0xcd) & 0xff));
    const expected = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      expected[i] = (sk[i % sk.length] ^ msg[i % msg.length] ^ (i * 7)) & 0xff;
    }
    return sig.every((b, i) => b === expected[i]);
  },
}));

// Import AFTER mocks are registered.
import { sealMessage, openBox } from '../pipeline';

// ---------------------------------------------------------------------------
// Round-trip — successful decryption
// ---------------------------------------------------------------------------

describe('sealMessage / openBox — round-trips', () => {
  it('recovers plaintext when all 3 passwords are correct', async () => {
    const msg = 'the quick brown fox jumps over the lazy dog';
    const passwords: [string, string, string] = ['alpha', 'bravo', 'charlie'];

    const box = await sealMessage(msg, passwords);
    const result = await openBox(box, passwords);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.message).toBe(msg);
      expect(result.validShareCount).toBe(3);
    }
  });

  it('recovers plaintext with the first two passwords (shares 1+2)', async () => {
    const msg = 'threshold met with first two';
    const passwords: [string, string, string] = ['one', 'two', 'three'];

    const box = await sealMessage(msg, passwords);
    const result = await openBox(box, ['one', 'two', null]);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.message).toBe(msg);
      expect(result.validShareCount).toBe(2);
    }
  });

  it('recovers plaintext with the last two passwords (shares 2+3)', async () => {
    const msg = 'threshold met with last two';
    const passwords: [string, string, string] = ['x', 'y', 'z'];

    const box = await sealMessage(msg, passwords);
    const result = await openBox(box, [null, 'y', 'z']);

    expect(result.success).toBe(true);
    if (result.success) expect(result.message).toBe(msg);
  });

  it('recovers plaintext with first and last passwords (shares 1+3)', async () => {
    const msg = 'threshold met with outer two';
    const passwords: [string, string, string] = ['p', 'q', 'r'];

    const box = await sealMessage(msg, passwords);
    const result = await openBox(box, ['p', null, 'r']);

    expect(result.success).toBe(true);
    if (result.success) expect(result.message).toBe(msg);
  });

  it('preserves arbitrary Unicode in the plaintext', async () => {
    const msg = 'Launch code: 🔐 ALPHA-7749-ZULU — día d\'acció';
    const passwords: [string, string, string] = ['fortress', 'bastion', 'citadel'];

    const box = await sealMessage(msg, passwords);
    const result = await openBox(box, passwords);

    expect(result.success).toBe(true);
    if (result.success) expect(result.message).toBe(msg);
  });
});

// ---------------------------------------------------------------------------
// Threshold failures — insufficient shares
// ---------------------------------------------------------------------------

describe('openBox — threshold failures', () => {
  it('fails with only 1 correct password (below threshold)', async () => {
    const passwords: [string, string, string] = ['a', 'b', 'c'];
    const box = await sealMessage('secret', passwords);

    const result = await openBox(box, ['a', null, null]);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.validShareCount).toBe(1);
      expect(result.gibberish).toBeInstanceOf(Uint8Array);
      expect(result.gibberish.length).toBeGreaterThan(0);
    }
  });

  it('fails with no passwords supplied', async () => {
    const box = await sealMessage('secret', ['a', 'b', 'c']);
    const result = await openBox(box, [null, null, null]);

    expect(result.success).toBe(false);
    if (!result.success) expect(result.validShareCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Wrong passwords
// ---------------------------------------------------------------------------

describe('openBox — wrong passwords', () => {
  it('fails when all 3 passwords are wrong', async () => {
    const passwords: [string, string, string] = ['a', 'b', 'c'];
    const box = await sealMessage('secret', passwords);

    const result = await openBox(box, ['x', 'y', 'z']);
    expect(result.success).toBe(false);
  });

  it('fails when 2 of 3 passwords are wrong', async () => {
    const passwords: [string, string, string] = ['a', 'b', 'c'];
    const box = await sealMessage('secret', passwords);

    // Only 'a' is correct → 1 valid share < threshold 2
    const result = await openBox(box, ['a', 'wrong', 'wrong']);
    expect(result.success).toBe(false);
    if (!result.success) expect(result.validShareCount).toBe(1);
  });

  it('fails when correct password is supplied for the wrong slot', async () => {
    // 'a' belongs to slot 0, but we pass it in slot 1
    const passwords: [string, string, string] = ['a', 'b', 'c'];
    const box = await sealMessage('secret', passwords);

    // Swap positions: 'b' in slot 0, 'a' in slot 1, null in slot 2
    const result = await openBox(box, ['b', 'a', null]);
    // 'b' in slot 0 decrypts the wrong SK → fails; 'a' in slot 1 is wrong pk
    // Either both fail (0 valid shares) or at best 1 succeeds — never 2.
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// HAETAE signature verification
// ---------------------------------------------------------------------------

describe('openBox — HAETAE signature verification', () => {
  it('rejects containers with a tampered signature', async () => {
    const passwords: [string, string, string] = ['p', 'q', 'r'];
    const box = await sealMessage('sensitive data', passwords);

    // Flip the first byte of the HAETAE signature.
    const tampered = { ...box, signature: box.signature.slice() };
    tampered.signature[0] ^= 0xff;

    const result = await openBox(tampered, passwords);

    expect(result.success).toBe(false);
    // HAETAE verify fails before passwords are tried → validShareCount = 0
    if (!result.success) expect(result.validShareCount).toBe(0);
  });

  it('rejects containers with a completely different signature', async () => {
    const passwords: [string, string, string] = ['p', 'q', 'r'];
    const box = await sealMessage('sensitive data', passwords);

    const tampered = { ...box, signature: crypto.getRandomValues(new Uint8Array(box.signature.length)) };
    const result = await openBox(tampered, passwords);

    expect(result.success).toBe(false);
  });

  it('rejects containers with a tampered ciphertext (signature covers it)', async () => {
    const passwords: [string, string, string] = ['p', 'q', 'r'];
    const box = await sealMessage('sensitive data', passwords);

    const tampered = { ...box, ciphertext: box.ciphertext.slice() };
    tampered.ciphertext[0] ^= 0xff;

    // containerData changes → HAETAE verify fails
    const result = await openBox(tampered, passwords);
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// SealedBox shape
// ---------------------------------------------------------------------------

describe('sealMessage — returned SealedBox structure', () => {
  it('has exactly 3 wrappedShares', async () => {
    const box = await sealMessage('test', ['a', 'b', 'c']);
    expect(box.wrappedShares).toHaveLength(3);
  });

  it('wrappedShares have all required fields', async () => {
    const box = await sealMessage('test', ['a', 'b', 'c']);
    for (const ws of box.wrappedShares) {
      expect(ws.salt).toBeInstanceOf(Uint8Array);
      expect(ws.kemCiphertext).toBeInstanceOf(Uint8Array);
      expect(ws.wrappedShare).toBeInstanceOf(Uint8Array);
      expect(ws.shareNonce).toBeInstanceOf(Uint8Array);
      expect(ws.publicKey).toBeInstanceOf(Uint8Array);
      expect(ws.wrappedSecretKey).toBeInstanceOf(Uint8Array);
      expect(ws.skNonce).toBeInstanceOf(Uint8Array);
    }
  });

  it('has a 12-byte nonce', async () => {
    const box = await sealMessage('nonce test', ['a', 'b', 'c']);
    expect(box.nonce.length).toBe(12);
  });

  it('box nonces are different across seals (random)', async () => {
    const passwords: [string, string, string] = ['x', 'y', 'z'];
    const [box1, box2] = await Promise.all([
      sealMessage('same', passwords),
      sealMessage('same', passwords),
    ]);
    // Two seals of identical plaintext with identical passwords must produce
    // different ciphertexts (IND-CPA property — random nonces / keys).
    expect(toHex(box1.nonce)).not.toBe(toHex(box2.nonce));
  });

  it('has a non-empty signature and sigPublicKey', async () => {
    const box = await sealMessage('signing test', ['a', 'b', 'c']);
    expect(box.signature.length).toBeGreaterThan(0);
    expect(box.sigPublicKey.length).toBeGreaterThan(0);
  });

  it('createdAt is an ISO timestamp', async () => {
    const box = await sealMessage('time test', ['a', 'b', 'c']);
    expect(() => new Date(box.createdAt).toISOString()).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toHex(arr: Uint8Array): string {
  return Array.from(arr)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
