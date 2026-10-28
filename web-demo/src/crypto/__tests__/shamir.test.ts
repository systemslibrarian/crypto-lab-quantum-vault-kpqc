import { describe, it, expect } from 'vitest';
import { splitSecret, reconstructSecret } from '../shamir';

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

describe('splitSecret / reconstructSecret', () => {
  it('round-trips a 32-byte secret with 2-of-3 using any two shares', () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const shares = splitSecret(secret, 2, 3);
    expect(shares).toHaveLength(3);

    // All three pairs must reconstruct correctly.
    const [s1, s2, s3] = shares;
    expect(Array.from(reconstructSecret([s1, s2]))).toEqual(Array.from(secret));
    expect(Array.from(reconstructSecret([s1, s3]))).toEqual(Array.from(secret));
    expect(Array.from(reconstructSecret([s2, s3]))).toEqual(Array.from(secret));
  });

  it('round-trips a 32-byte secret with all 3 shares', () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const shares = splitSecret(secret, 2, 3);
    expect(Array.from(reconstructSecret(shares))).toEqual(Array.from(secret));
  });

  it('round-trips a 3-of-5 scheme using any 3 of 5 shares', () => {
    const secret = new Uint8Array(32).fill(0xab);
    const shares = splitSecret(secret, 3, 5);
    expect(shares).toHaveLength(5);

    // Use non-adjacent subset [0, 2, 4] to catch polynomial evaluation bugs.
    const subset = [shares[0], shares[2], shares[4]];
    expect(Array.from(reconstructSecret(subset))).toEqual(Array.from(secret));
  });

  it('round-trips the minimum 2-of-2 scheme', () => {
    const secret = crypto.getRandomValues(new Uint8Array(16));
    const shares = splitSecret(secret, 2, 2);
    expect(shares).toHaveLength(2);
    expect(Array.from(reconstructSecret(shares))).toEqual(Array.from(secret));
  });

  it('round-trips a single-byte secret', () => {
    const secret = new Uint8Array([0xfe]);
    const shares = splitSecret(secret, 2, 3);
    expect(Array.from(reconstructSecret([shares[0], shares[1]]))).toEqual([0xfe]);
  });

  it('round-trips an all-zero secret', () => {
    const secret = new Uint8Array(32); // all zeros
    const shares = splitSecret(secret, 2, 3);
    expect(Array.from(reconstructSecret([shares[0], shares[2]]))).toEqual(
      Array.from(secret),
    );
  });

  it('round-trips an all-0xFF secret', () => {
    const secret = new Uint8Array(32).fill(0xff);
    const shares = splitSecret(secret, 2, 3);
    expect(Array.from(reconstructSecret([shares[1], shares[2]]))).toEqual(
      Array.from(secret),
    );
  });

  it('share indices are 1-based and unique', () => {
    const shares = splitSecret(new Uint8Array([42]), 2, 5);
    const indices = shares.map(s => s.index);
    expect(indices).toEqual([1, 2, 3, 4, 5]);
    // Indices must be unique
    expect(new Set(indices).size).toBe(5);
  });

  // ---------------------------------------------------------------------------
  // Threshold behaviour: fewer shares → unauthenticated candidate (not an error)
  // ---------------------------------------------------------------------------

  it('returns a stable candidate without enforcing the caller threshold', () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    // 3-of-3 scheme: two shares are insufficient, but reconstructSecret does
    // not receive the policy and therefore interpolates the points it is given.
    const shares = splitSecret(secret, 3, 3);
    const candidate = reconstructSecret([shares[0], shares[1]]);
    const reordered = reconstructSecret([shares[1], shares[0]]);
    expect(candidate).toHaveLength(secret.length);
    expect(Array.from(reordered)).toEqual(Array.from(candidate));
  });

  it('single-share interpolation returns that share as a candidate', () => {
    const data = new Uint8Array([0x42, 0x00, 0xff]);
    const candidate = reconstructSecret([{ index: 1, data }]);
    expect(Array.from(candidate)).toEqual(Array.from(data));
  });

  // ---------------------------------------------------------------------------
  // Share payloads have same length as the secret
  // ---------------------------------------------------------------------------

  it('share data length equals secret length', () => {
    const secret = new Uint8Array(64);
    crypto.getRandomValues(secret);
    const shares = splitSecret(secret, 2, 3);
    for (const share of shares) {
      expect(share.data.length).toBe(64);
    }
  });
});

// ---------------------------------------------------------------------------
// Invalid parameter handling
// ---------------------------------------------------------------------------

describe('splitSecret — invalid params', () => {
  it('throws when threshold < 2', () => {
    expect(() => splitSecret(new Uint8Array([1]), 1, 3)).toThrow();
  });

  it('throws when threshold > totalShares', () => {
    expect(() => splitSecret(new Uint8Array([1]), 4, 3)).toThrow();
  });

  it('throws when secret is empty', () => {
    expect(() => splitSecret(new Uint8Array(0), 2, 3)).toThrow();
  });

  it('rejects fractional or out-of-field share counts', () => {
    expect(() => splitSecret(new Uint8Array([1]), 2.5, 3)).toThrow();
    expect(() => splitSecret(new Uint8Array([1]), 2, 256)).toThrow();
  });
});

describe('reconstructSecret — invalid shares', () => {
  it('rejects duplicate or zero indices', () => {
    const data = new Uint8Array([1, 2]);
    expect(() => reconstructSecret([
      { index: 1, data },
      { index: 1, data: data.slice() },
    ])).toThrow('unique integers');
    expect(() => reconstructSecret([{ index: 0, data }])).toThrow('unique integers');
  });

  it('rejects unequal payload lengths', () => {
    expect(() => reconstructSecret([
      { index: 1, data: new Uint8Array(2) },
      { index: 2, data: new Uint8Array(3) },
    ])).toThrow('equal lengths');
  });
});
