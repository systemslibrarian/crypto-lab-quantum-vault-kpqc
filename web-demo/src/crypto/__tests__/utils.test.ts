import { describe, it, expect } from 'vitest';
import {
  toBase64,
  fromBase64,
  encode,
  decode,
  concatBytes,
  buf,
} from '../utils';

// ---------------------------------------------------------------------------
// Base64 codec
// ---------------------------------------------------------------------------

describe('toBase64 / fromBase64', () => {
  it('round-trips arbitrary bytes', () => {
    const input = new Uint8Array([0, 1, 127, 128, 255]);
    expect(Array.from(fromBase64(toBase64(input)))).toEqual(Array.from(input));
  });

  it('round-trips an empty array', () => {
    const input = new Uint8Array(0);
    expect(Array.from(fromBase64(toBase64(input)))).toEqual([]);
  });

  it('produces known output for known input', () => {
    // "Man" → "TWFu" in standard base64
    const input = new Uint8Array([77, 97, 110]);
    expect(toBase64(input)).toBe('TWFu');
  });

  it('decodes known base64 string correctly', () => {
    const result = fromBase64('SGVsbG8='); // "Hello"
    expect(Array.from(result)).toEqual([72, 101, 108, 108, 111]);
  });

  it('round-trips a 32-byte AES key', () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const encoded = toBase64(key);
    const decoded = fromBase64(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(key));
  });

  it('round-trips alignment-critical sizes: 1, 2, 3, 4 bytes', () => {
    for (let len = 1; len <= 4; len++) {
      const input = new Uint8Array(len).map((_, i) => i + 1);
      expect(Array.from(fromBase64(toBase64(input)))).toEqual(Array.from(input));
    }
  });
});

// ---------------------------------------------------------------------------
// Text encode / decode
// ---------------------------------------------------------------------------

describe('encode / decode', () => {
  it('round-trips ASCII text', () => {
    const text = 'the quick brown fox';
    expect(decode(encode(text))).toBe(text);
  });

  it('round-trips Unicode text', () => {
    const text = 'Héllo Wörld — 日本語 🔐';
    expect(decode(encode(text))).toBe(text);
  });

  it('round-trips an empty string', () => {
    expect(decode(encode(''))).toBe('');
  });
});

// ---------------------------------------------------------------------------
// concatBytes
// ---------------------------------------------------------------------------

describe('concatBytes', () => {
  it('concatenates two non-empty arrays', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5, 6]);
    expect(Array.from(concatBytes(a, b))).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it('handles an empty first argument', () => {
    const a = new Uint8Array(0);
    const b = new Uint8Array([7, 8]);
    expect(Array.from(concatBytes(a, b))).toEqual([7, 8]);
  });

  it('handles an empty second argument', () => {
    const a = new Uint8Array([9]);
    const b = new Uint8Array(0);
    expect(Array.from(concatBytes(a, b))).toEqual([9]);
  });

  it('handles multiple arrays', () => {
    const parts = [
      new Uint8Array([1]),
      new Uint8Array([2, 3]),
      new Uint8Array([4, 5, 6]),
    ];
    expect(Array.from(concatBytes(...parts))).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it('returns an empty array when all inputs are empty', () => {
    expect(Array.from(concatBytes(new Uint8Array(0)))).toEqual([]);
  });

  it('total length equals sum of part lengths', () => {
    const a = new Uint8Array(13);
    const b = new Uint8Array(19);
    expect(concatBytes(a, b).length).toBe(32);
  });
});

// ---------------------------------------------------------------------------
// buf — type-assertion helper
// ---------------------------------------------------------------------------

describe('buf', () => {
  it('returns the same bytes', () => {
    const input = new Uint8Array([1, 2, 3, 4]);
    const output = buf(input);
    expect(Array.from(output)).toEqual([1, 2, 3, 4]);
  });
});
