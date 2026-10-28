import { describe, expect, it } from 'vitest';
import { toBase64 } from '../../crypto/utils';
import { deserializeSealedBox, validateVaultState } from '../state';
import type { VaultBox } from '../state';

const b64 = (length: number): string => toBase64(new Uint8Array(length).fill(1));

function validBox(): VaultBox {
  return {
    ciphertext: b64(32),
    nonce: b64(12),
    wrappedShares: [0, 1, 2].map(() => ({
      salt: b64(16),
      kemCiphertext: b64(672),
      wrappedShare: b64(48),
      shareNonce: b64(12),
      publicKey: b64(672),
      wrappedSecretKey: b64(848),
      skNonce: b64(12),
      iterations: 600_000,
    })),
    signature: b64(1400),
    sigPublicKey: b64(992),
    createdAt: '2026-10-23T00:00:00.000Z',
  };
}

describe('deserializeSealedBox validation', () => {
  it('accepts the exact active field sizes', () => {
    const parsed = deserializeSealedBox(validBox());
    expect(parsed.wrappedShares).toHaveLength(3);
    expect(parsed.wrappedShares[0].iterations).toBe(600_000);
  });

  it('rejects wrong-sized wrapped shares and secret keys', () => {
    const share = validBox();
    share.wrappedShares[0].wrappedShare = b64(47);
    expect(() => deserializeSealedBox(share)).toThrow('wrappedShare');

    const secretKey = validBox();
    secretKey.wrappedShares[0].wrappedSecretKey = b64(849);
    expect(() => deserializeSealedBox(secretKey)).toThrow('wrappedSecretKey');
  });

  it('rejects PBKDF2 work factors outside the bounded integer range', () => {
    for (const iterations of [99_999, 1_000_001, 600_000.5]) {
      const box = validBox();
      box.wrappedShares[0].iterations = iterations;
      expect(() => deserializeSealedBox(box)).toThrow('must be an integer');
    }
  });

  it('rejects a non-string creation timestamp', () => {
    const box = validBox() as unknown as Record<string, unknown>;
    box.createdAt = { injected: true };
    expect(() => deserializeSealedBox(box as unknown as VaultBox)).toThrow(
      'createdAt must be a canonical ISO timestamp',
    );
  });

  it('rejects non-canonical timestamps and non-string base64 fields', () => {
    const timestamp = validBox();
    timestamp.createdAt = 'October 23, 2026';
    expect(() => deserializeSealedBox(timestamp)).toThrow('canonical ISO timestamp');

    const binary = validBox() as unknown as Record<string, unknown>;
    binary.nonce = { coerced: 'base64' };
    expect(() => deserializeSealedBox(binary as unknown as VaultBox)).toThrow(
      'nonce" must be base64 text',
    );
  });
});

describe('validateVaultState', () => {
  it('accepts bounded 01-09 state and validates every stored box', () => {
    const parsed = validateVaultState({ version: 2, boxes: { '01': validBox() } });
    expect(parsed?.boxes['01']).toBeDefined();
  });

  it('rejects invalid keys, too many boxes, and malformed stored boxes', () => {
    expect(validateVaultState({ version: 2, boxes: { '10': validBox() } })).toBeNull();

    const boxes = Object.fromEntries(
      Array.from({ length: 10 }, (_, i) => [String(i + 1).padStart(2, '0'), validBox()]),
    );
    expect(validateVaultState({ version: 2, boxes })).toBeNull();

    const malformed = validBox();
    malformed.wrappedShares[0].wrappedShare = b64(47);
    expect(validateVaultState({ version: 2, boxes: { '01': malformed } })).toBeNull();
  });
});
