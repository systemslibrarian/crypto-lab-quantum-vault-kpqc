import { beforeEach, describe, expect, it, vi } from 'vitest';

const tracked = vi.hoisted(() => ({
  keypairSecret: new Uint8Array(32),
  encapsulatedSecret: new Uint8Array(32),
  decapsulatedSecret: new Uint8Array(32),
}));

vi.mock('../smaug', () => ({
  smaugKeypair: () => ({
    publicKey: new Uint8Array(672),
    secretKey: tracked.keypairSecret,
  }),
  smaugEncapsulate: () => ({
    ciphertext: new Uint8Array(672),
    sharedSecret: tracked.encapsulatedSecret,
  }),
  smaugDecapsulate: () => tracked.decapsulatedSecret,
}));

import { unwrapShare, wrapShare } from '../keywrap';
import type { WrappedShare } from '../keywrap';

beforeEach(() => {
  tracked.keypairSecret.fill(0xa1);
  tracked.encapsulatedSecret.fill(0xb2);
  tracked.decapsulatedSecret.fill(0xc3);
});

describe('key-wrap failure cleanup', () => {
  it('clears the generated SMAUG key and encapsulated secret when share encryption fails', async () => {
    const encrypt = vi.spyOn(crypto.subtle, 'encrypt').mockRejectedValue(
      new Error('injected share encryption failure'),
    );
    try {
      await expect(wrapShare(new Uint8Array(32), 'password')).rejects.toThrow(
        'injected share encryption failure',
      );
      expect(tracked.keypairSecret.every(byte => byte === 0)).toBe(true);
      expect(tracked.encapsulatedSecret.every(byte => byte === 0)).toBe(true);
    } finally {
      encrypt.mockRestore();
    }
  });

  it('clears recovered SMAUG and shared secrets when share decryption fails', async () => {
    const recoveredSecretKey = new Uint8Array(832).fill(0xd4);
    const decrypt = vi.spyOn(crypto.subtle, 'decrypt')
      .mockResolvedValueOnce(recoveredSecretKey.buffer)
      .mockRejectedValueOnce(new Error('injected share decryption failure'));
    const wrapped: WrappedShare = {
      salt: new Uint8Array(16),
      kemCiphertext: new Uint8Array(672),
      wrappedShare: new Uint8Array(48),
      shareNonce: new Uint8Array(12),
      publicKey: new Uint8Array(672),
      wrappedSecretKey: new Uint8Array(848),
      skNonce: new Uint8Array(12),
      iterations: 100_000,
    };

    try {
      await expect(unwrapShare(wrapped, 'password')).rejects.toThrow(
        'injected share decryption failure',
      );
      expect(recoveredSecretKey.every(byte => byte === 0)).toBe(true);
      expect(tracked.decapsulatedSecret.every(byte => byte === 0)).toBe(true);
    } finally {
      decrypt.mockRestore();
    }
  });
});
