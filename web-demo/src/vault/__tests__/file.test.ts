// Tests for .qvault file serialization, export, and import

import { describe, it, expect } from 'vitest';
import {
  serializeToQvault,
  deserializeFromQvault,
  importQvault,
  QvaultImportError,
} from '../../vault/file';
import type { SealedBox } from '../../crypto/pipeline';

// Create a minimal valid SealedBox for testing serialization
function createMockSealedBox(): SealedBox {
  return {
    ciphertext: new Uint8Array([1, 2, 3, 4, 5]),
    nonce: new Uint8Array(12).fill(1), // 12 bytes
    wrappedShares: [
      {
        salt: new Uint8Array(16).fill(1), // 16 bytes
        kemCiphertext: new Uint8Array(672).fill(1), // 672 bytes
        wrappedShare: new Uint8Array(48).fill(1),
        shareNonce: new Uint8Array(12).fill(1), // 12 bytes
        publicKey: new Uint8Array(672).fill(1), // 672 bytes
        wrappedSecretKey: new Uint8Array(848).fill(1), // SK size + tag
        skNonce: new Uint8Array(12).fill(1), // 12 bytes
        iterations: 600_000,
      },
      {
        salt: new Uint8Array(16).fill(2),
        kemCiphertext: new Uint8Array(672).fill(2),
        wrappedShare: new Uint8Array(48).fill(2),
        shareNonce: new Uint8Array(12).fill(2),
        publicKey: new Uint8Array(672).fill(2),
        wrappedSecretKey: new Uint8Array(848).fill(2),
        skNonce: new Uint8Array(12).fill(2),
        iterations: 600_000,
      },
      {
        salt: new Uint8Array(16).fill(3),
        kemCiphertext: new Uint8Array(672).fill(3),
        wrappedShare: new Uint8Array(48).fill(3),
        shareNonce: new Uint8Array(12).fill(3),
        publicKey: new Uint8Array(672).fill(3),
        wrappedSecretKey: new Uint8Array(848).fill(3),
        skNonce: new Uint8Array(12).fill(3),
        iterations: 600_000,
      },
    ],
    signature: new Uint8Array(1400).fill(1), // HAETAE sig
    sigPublicKey: new Uint8Array(992).fill(1), // 992 bytes
    createdAt: '2026-03-15T00:00:00.000Z',
  };
}

describe('serializeToQvault', () => {
  it('produces valid JSON with version and algorithm fields', () => {
    const box = createMockSealedBox();
    const json = serializeToQvault(box);
    const parsed = JSON.parse(json);

    expect(parsed.version).toBe('qvault-v1');
    expect(parsed.algorithm).toEqual({
      kem: 'smaug-t-level1',
      sig: 'haetae-mode2',
      symmetric: 'aes-256-gcm',
      kdf: 'pbkdf2-sha256',
    });
    expect(parsed.participants).toHaveLength(3);
    expect(parsed.participants[0].label).toBe('Alice');
    expect(parsed.participants[1].label).toBe('Bob');
    expect(parsed.participants[2].label).toBe('Carol');
  });

  it('includes all required fields', () => {
    const box = createMockSealedBox();
    const json = serializeToQvault(box);
    const parsed = JSON.parse(json);

    expect(parsed.ciphertext).toBeDefined();
    expect(parsed.nonce).toBeDefined();
    expect(parsed.signature).toBeDefined();
    expect(parsed.signaturePublicKey).toBeDefined();
    expect(parsed.createdAt).toBe('2026-03-15T00:00:00.000Z');
  });
});

describe('deserializeFromQvault', () => {
  it('roundtrip serialization preserves all data', () => {
    const original = createMockSealedBox();
    const json = serializeToQvault(original);
    const restored = deserializeFromQvault(json);

    // Compare binary fields
    expect(Array.from(restored.ciphertext)).toEqual(Array.from(original.ciphertext));
    expect(Array.from(restored.nonce)).toEqual(Array.from(original.nonce));
    expect(Array.from(restored.signature)).toEqual(Array.from(original.signature));
    expect(Array.from(restored.sigPublicKey)).toEqual(Array.from(original.sigPublicKey));
    expect(restored.createdAt).toBe(original.createdAt);

    // Compare wrapped shares
    expect(restored.wrappedShares).toHaveLength(3);
    for (let i = 0; i < 3; i++) {
      const orig = original.wrappedShares[i];
      const rest = restored.wrappedShares[i];
      expect(Array.from(rest.salt)).toEqual(Array.from(orig.salt));
      expect(Array.from(rest.kemCiphertext)).toEqual(Array.from(orig.kemCiphertext));
      expect(Array.from(rest.wrappedShare)).toEqual(Array.from(orig.wrappedShare));
      expect(Array.from(rest.shareNonce)).toEqual(Array.from(orig.shareNonce));
      expect(Array.from(rest.publicKey)).toEqual(Array.from(orig.publicKey));
      expect(Array.from(rest.wrappedSecretKey)).toEqual(Array.from(orig.wrappedSecretKey));
      expect(Array.from(rest.skNonce)).toEqual(Array.from(orig.skNonce));
      expect(rest.iterations).toBe(orig.iterations);
    }
  });

  it('rejects invalid JSON', () => {
    expect(() => deserializeFromQvault('not json {')).toThrow(QvaultImportError);
    expect(() => deserializeFromQvault('not json {')).toThrow('Invalid file format');
  });

  it('rejects missing version', () => {
    const json = JSON.stringify({
      ciphertext: 'AQID',
      nonce: 'AQEB',
      participants: [],
      signature: 'sig',
      signaturePublicKey: 'pk',
      createdAt: '2026-01-01',
    });
    expect(() => deserializeFromQvault(json)).toThrow('missing version');
  });

  it('rejects unsupported version', () => {
    const box = createMockSealedBox();
    const json = serializeToQvault(box);
    const modified = json.replace('qvault-v1', 'qvault-v99');
    expect(() => deserializeFromQvault(modified)).toThrow('Unsupported vault format');
  });

  it('rejects missing required fields', () => {
    const base = {
      version: 'qvault-v1',
      algorithm: { kem: 'smaug-t-level1', sig: 'haetae-mode2' },
    };

    // Missing ciphertext
    expect(() => deserializeFromQvault(JSON.stringify(base))).toThrow('missing ciphertext');
  });

  it('rejects wrong participant count', () => {
    const box = createMockSealedBox();
    const json = serializeToQvault(box);
    const parsed = JSON.parse(json);
    parsed.participants = parsed.participants.slice(0, 2); // Only 2 participants
    expect(() => deserializeFromQvault(JSON.stringify(parsed))).toThrow('Invalid participant count');
  });

  it('rejects missing, renamed, or reordered participant labels', () => {
    const missing = JSON.parse(serializeToQvault(createMockSealedBox()));
    delete missing.participants[0].label;
    expect(() => deserializeFromQvault(JSON.stringify(missing))).toThrow(
      'missing label',
    );

    const renamed = JSON.parse(serializeToQvault(createMockSealedBox()));
    renamed.participants[1].label = 'Mallory';
    expect(() => deserializeFromQvault(JSON.stringify(renamed))).toThrow(
      'expected Bob',
    );

    const reordered = JSON.parse(serializeToQvault(createMockSealedBox()));
    [reordered.participants[0], reordered.participants[1]] =
      [reordered.participants[1], reordered.participants[0]];
    expect(() => deserializeFromQvault(JSON.stringify(reordered))).toThrow(
      'expected Alice',
    );
  });

  it('rejects unsupported algorithm', () => {
    const box = createMockSealedBox();
    const json = serializeToQvault(box);
    const parsed = JSON.parse(json);
    parsed.algorithm.kem = 'kyber-1024';
    expect(() => deserializeFromQvault(JSON.stringify(parsed))).toThrow('Unsupported algorithm');
  });

  it('rejects missing or incomplete algorithm metadata', () => {
    const missing = JSON.parse(serializeToQvault(createMockSealedBox()));
    delete missing.algorithm;
    expect(() => deserializeFromQvault(JSON.stringify(missing))).toThrow(
      'missing algorithm',
    );

    const incomplete = JSON.parse(serializeToQvault(createMockSealedBox()));
    delete incomplete.algorithm.kdf;
    expect(() => deserializeFromQvault(JSON.stringify(incomplete))).toThrow(
      'Unsupported algorithm',
    );

    const extra = JSON.parse(serializeToQvault(createMockSealedBox()));
    extra.algorithm.unreviewed = 'attacker-controlled';
    expect(() => deserializeFromQvault(JSON.stringify(extra))).toThrow(
      'Unsupported algorithm metadata fields',
    );
  });

  it('rejects a non-timestamp createdAt value', () => {
    const parsed = JSON.parse(serializeToQvault(createMockSealedBox()));
    parsed.createdAt = { attackerControlled: true };
    expect(() => deserializeFromQvault(JSON.stringify(parsed))).toThrow(
      'expected a canonical ISO timestamp',
    );
  });

  it('rejects a non-canonical creation timestamp', () => {
    const parsed = JSON.parse(serializeToQvault(createMockSealedBox()));
    parsed.createdAt = 'March 15, 2026';
    expect(() => deserializeFromQvault(JSON.stringify(parsed))).toThrow(
      'expected a canonical ISO timestamp',
    );
  });

  it('rejects corrupted base64 data', () => {
    const box = createMockSealedBox();
    const json = serializeToQvault(box);
    const parsed = JSON.parse(json);
    parsed.ciphertext = '!!!invalid-base64!!!';
    expect(() => deserializeFromQvault(JSON.stringify(parsed))).toThrow('Corrupted data');
  });

  it('rejects wrong field lengths', () => {
    const box = createMockSealedBox();
    const json = serializeToQvault(box);
    const parsed = JSON.parse(json);
    // nonce should be 12 bytes, but we provide wrong length
    parsed.nonce = btoa('short');
    expect(() => deserializeFromQvault(JSON.stringify(parsed))).toThrow('Corrupted data');
  });

  it('defaults iterations to 100_000 when missing', () => {
    const box = createMockSealedBox();
    const json = serializeToQvault(box);
    const parsed = JSON.parse(json);
    // Remove iterations from participants
    parsed.participants.forEach((p: Record<string, unknown>) => {
      delete p.iterations;
    });
    const restored = deserializeFromQvault(JSON.stringify(parsed));
    expect(restored.wrappedShares[0].iterations).toBe(100_000);
  });

  it('rejects unsafe or denial-of-service PBKDF2 iteration counts', () => {
    const parsed = JSON.parse(serializeToQvault(createMockSealedBox()));
    for (const iterations of [0, 99_999, 1_000_001, 600_000.5, '600000']) {
      parsed.participants[0].iterations = iterations;
      expect(() => deserializeFromQvault(JSON.stringify(parsed))).toThrow(
        'PBKDF2 iterations must be an integer',
      );
    }
  });

  it('rejects oversized wrapped secrets and wrong-sized wrapped shares', () => {
    const parsed = JSON.parse(serializeToQvault(createMockSealedBox()));
    parsed.participants[0].wrappedSecretKey = btoa('x'.repeat(849));
    expect(() => deserializeFromQvault(JSON.stringify(parsed))).toThrow(
      'wrappedSecretKey',
    );

    const second = JSON.parse(serializeToQvault(createMockSealedBox()));
    second.participants[0].wrappedShare = btoa('x'.repeat(47));
    expect(() => deserializeFromQvault(JSON.stringify(second))).toThrow(
      'wrappedShare',
    );
  });
});

describe('file import bounds', () => {
  it('rejects an oversized file before reading its text', async () => {
    let read = false;
    const oversized = {
      size: 90 * 1024 * 1024 + 1,
      text: async () => {
        read = true;
        return '{}';
      },
    } as File;

    await expect(importQvault(oversized)).rejects.toThrow('Import file exceeds');
    expect(read).toBe(false);
  });
});

// Note: verifyQvaultSignature requires initialized WASM modules,
// which are not available in unit tests. Integration tests should cover this.
