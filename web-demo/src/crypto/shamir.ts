// Shamir Secret Sharing over GF(2^8)
// Irreducible polynomial: 0x11D  (x^8 + x^4 + x^3 + x^2 + 1)
// Generator: 2 — has order 255 with this polynomial, making it a primitive
// element and ensuring the EXP/LOG tables cover all 255 non-zero elements.
// (0x11B = AES polynomial is irreducible but 2 has order 51 there, not 255.)
//
// Critical property: reconstructing with fewer than `threshold` shares produces
// mathematically incorrect output (wrong bytes), NOT an error. This is the
// fundamental security property of Shamir SSS and is what drives the gibberish
// reveal on retrieval failure.

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

function evaluatePolynomial(coefficients: number[], x: number): number {
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
  if (threshold < 2 || threshold > totalShares) {
    throw new Error('Invalid Shamir threshold parameters');
  }

  const shares: Share[] = Array.from({ length: totalShares }, (_, i) => ({
    index: i + 1,
    data: new Uint8Array(secret.length),
  }));

  // Reuse a single buffer for random coefficients so we can wipe it once done
  // rather than creating a fresh allocation (and GC-visible ghost) each iteration.
  const rand = new Uint8Array(threshold - 1);
  // Scratch buffer for rejection-sampling the leading coefficient; hoisted for
  // the same reason as `rand` and wiped alongside it.
  const redraw = new Uint8Array(1);

  // Position of the leading coefficient a_{threshold-1} inside `rand`.
  const leadingIdx = threshold - 2;

  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    // Polynomial: f(x) = secret[i] + c1*x + c2*x^2 + ... (over GF(256))
    const coefficients: number[] = [secret[byteIdx]];
    crypto.getRandomValues(rand);

    // The LEADING coefficient must be nonzero so the polynomial has degree
    // exactly threshold-1; a zero leading term would drop the degree and let
    // threshold-1 shares reconstruct. Resample (rejection sampling) rather than
    // mapping 0 -> 1, which would make the value 1 twice as likely as any other.
    while (rand[leadingIdx] === 0) {
      crypto.getRandomValues(redraw);
      rand[leadingIdx] = redraw[0];
    }

    // Every OTHER coefficient is uniform over the full field, 0 included,
    // exactly as in Shamir's 1979 construction. Forcing them nonzero would
    // leak: it rules out one candidate per secret byte for a holder of a single
    // share, which is precisely the "a single share reveals NOTHING" claim.
    for (let i = 0; i < threshold - 1; i++) {
      coefficients.push(rand[i]);
    }
    for (let s = 0; s < totalShares; s++) {
      shares[s].data[byteIdx] = evaluatePolynomial(coefficients, shares[s].index);
    }
  }

  // Wipe the coefficient buffer — polynomial coefficients are as sensitive as
  // share data since knowing them plus any one share reveals each secret byte.
  rand.fill(0);
  redraw.fill(0);

  return shares;
}

function lagrangeInterpolate(points: { x: number; y: number }[]): number {
  // Evaluate the unique polynomial through `points` at x = 0
  let secret = 0;
  for (let i = 0; i < points.length; i++) {
    let basis = 1; // Lagrange basis polynomial L_i(0)
    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      // L_i(0) *= (0 ^ x_j) / (x_i ^ x_j)   (XOR = subtraction in GF(256))
      basis = gfMul(basis, gfDiv(points[j].x, points[i].x ^ points[j].x));
    }
    secret ^= gfMul(points[i].y, basis);
  }
  return secret;
}

export function reconstructSecret(shares: Share[]): Uint8Array {
  if (shares.length === 0) throw new Error('No shares provided');
  const length = shares[0].data.length;
  const result = new Uint8Array(length);
  for (let byteIdx = 0; byteIdx < length; byteIdx++) {
    const points = shares.map(s => ({ x: s.index, y: s.data[byteIdx] }));
    result[byteIdx] = lagrangeInterpolate(points);
  }
  return result;
}
