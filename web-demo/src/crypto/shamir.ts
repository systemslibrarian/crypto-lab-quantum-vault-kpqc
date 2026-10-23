// Shamir Secret Sharing over GF(2^8)
// Irreducible polynomial: 0x11D  (x^8 + x^4 + x^3 + x^2 + 1)
// Generator: 2 — has order 255 with this polynomial, making it a primitive
// element and ensuring the EXP/LOG tables cover all 255 non-zero elements.
// (0x11B = AES polynomial is irreducible but 2 has order 51 there, not 255.)
//
// Critical property: reconstructing with fewer than `threshold` shares produces
// an unauthenticated candidate, NOT an error. Conditioned on the observed shares,
// each true secret byte remains uniform over GF(256), so the candidate
// coincides with the true byte with probability 1/256 — for the 32-byte key this
// demo splits, an accidentally correct reconstruction has probability 256^-32.
// That residual chance is not a defect: it is what "every candidate secret is
// equally likely" means, and a scheme where under-threshold output could never
// be right would be leaking.

const EXP = new Uint8Array(512); // EXP[i] = generator^i  (extended for easy mul)
const LOG = new Uint8Array(256); // LOG[x] = i  where  generator^i = x

(function initTables(): void {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x = x << 1;
    if (x & 0x100) x ^= 0x11d; // reduce by irreducible polynomial (0x11d: generator 2 has order 255)
  }
  // Extended table so gfMul can index LOG[a]+LOG[b] without extra modular step
  for (let i = 255; i < 512; i++) {
    EXP[i] = EXP[i - 255];
  }
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error('GF(256) division by zero');
  if (a === 0) return 0;
  return EXP[((LOG[a] - LOG[b]) % 255 + 255) % 255];
}

function evaluatePolynomial(coefficients: Uint8Array, x: number): number {
  // Horner's method over GF(256)
  let result = 0;
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = gfMul(result, x) ^ coefficients[i]; // XOR = GF(256) addition
  }
  return result;
}

export interface Share {
  index: number;  // 1-based x-coordinate on the polynomial
  data: Uint8Array;
}

export function splitSecret(
  secret: Uint8Array,
  threshold: number,
  totalShares: number,
): Share[] {
  if (secret.length === 0) {
    throw new Error('Secret must not be empty');
  }
  if (
    !Number.isInteger(threshold) ||
    !Number.isInteger(totalShares) ||
    threshold < 2 ||
    threshold > totalShares ||
    totalShares > 255
  ) {
    throw new Error('Invalid Shamir threshold parameters');
  }

  const shares: Share[] = Array.from({ length: totalShares }, (_, i) => ({
    index: i + 1,
    data: new Uint8Array(secret.length),
  }));

  // Reuse one typed buffer for the secret byte and random coefficients. An
  // ordinary number[] per byte would leave GC-managed copies that cannot be
  // wiped. The finally block also covers RNG or evaluation failures.
  const coefficients = new Uint8Array(threshold);
  let complete = false;
  try {
    for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
      // Polynomial: f(x) = secret[i] + c1*x + c2*x^2 + ... (over GF(256))
      coefficients[0] = secret[byteIdx];
      crypto.getRandomValues(coefficients.subarray(1));

      // EVERY non-constant coefficient — the leading one a_{threshold-1} included —
      // is uniform over the full field, 0 included, exactly as in Shamir's 1979
      // construction. Constraining any of them to be nonzero leaks: fix any
      // threshold-1 shares, and for each candidate secret there is exactly one
      // coefficient vector consistent with them; its leading coefficient varies
      // non-degenerately with the candidate, so barring 0 makes exactly one
      // candidate per secret byte unreachable. That is a 1/256 leak in precisely
      // the "a single share reveals NOTHING" claim — and at the shipped 2-of-3
      // setting the single non-constant coefficient IS the leading one, so the
      // constraint applied to every byte of every real key.
      //
      // The degree may therefore drop below threshold-1 (probability 1/256). That
      // is harmless: `threshold` points still determine a unique polynomial of
      // degree <= threshold-1, so reconstruction is unaffected; and a holder of
      // threshold-1 shares cannot distinguish a degenerate polynomial from a
      // full-degree one, so nothing is given away.
      for (let s = 0; s < totalShares; s++) {
        shares[s].data[byteIdx] = evaluatePolynomial(coefficients, shares[s].index);
      }
    }
    complete = true;
  } finally {
    // Coefficients plus any one share reveal the secret, so clear every exit.
    coefficients.fill(0);
    if (!complete) {
      for (const share of shares) share.data.fill(0);
    }
  }

  return shares;
}

function lagrangeInterpolateByte(shares: Share[], byteIdx: number): number {
  // Evaluate the unique polynomial through `shares` at x = 0 without creating
  // GC-managed copies of each sensitive share byte.
  let secret = 0;
  for (let i = 0; i < shares.length; i++) {
    let basis = 1; // Lagrange basis polynomial L_i(0)
    for (let j = 0; j < shares.length; j++) {
      if (i === j) continue;
      // L_i(0) *= (0 ^ x_j) / (x_i ^ x_j)   (XOR = subtraction in GF(256))
      basis = gfMul(
        basis,
        gfDiv(shares[j].index, shares[i].index ^ shares[j].index),
      );
    }
    secret ^= gfMul(shares[i].data[byteIdx], basis);
  }
  return secret;
}

export function reconstructSecret(shares: Share[]): Uint8Array {
  if (shares.length === 0) throw new Error('No shares provided');
  const length = shares[0].data.length;
  const indices = new Set<number>();
  for (const share of shares) {
    if (
      !Number.isInteger(share.index) ||
      share.index < 1 ||
      share.index > 255 ||
      indices.has(share.index)
    ) {
      throw new Error('Share indices must be unique integers from 1 to 255');
    }
    if (share.data.length !== length) {
      throw new Error('Share payloads must have equal lengths');
    }
    indices.add(share.index);
  }
  const result = new Uint8Array(length);
  for (let byteIdx = 0; byteIdx < length; byteIdx++) {
    result[byteIdx] = lagrangeInterpolateByte(shares, byteIdx);
  }
  return result;
}
