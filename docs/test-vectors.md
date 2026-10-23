# Quantum Vault — Cryptographic Test Vectors

**Version:** 1.0  
**Test file:** `crates/qv-core/tests/test_vectors.rs`

---

## Overview

This document describes the test vector strategy used in Quantum Vault.
Because several operations (key generation, share splitting) use OS-entropy
randomness, not all algorithm outputs can be pre-computed as static hex strings.
The strategy is therefore:

| Operation | Vector type | Justification |
|-----------|------------|---------------|
| AES-256-GCM encryption | NIST-sourced static | Deterministic given key+nonce+PT |
| GF(2⁸) arithmetic | Hand-computed static | Pure algebra, no randomness |
| Shamir split | Property-based (round-trip) | Non-deterministic coefficients |
| Shamir reconstruct | Static pre-computed | Given known shares, output is deterministic |
| Container encrypt/decrypt | Property-based | Non-deterministic KEM |
| Full pipeline | Property-based | Non-deterministic |

---

## 1. AES-256-GCM Static Vectors

### Vector AES-01 — NIST SP 800-38D, Test Case (256-bit key, empty message)

Source: NIST Cryptographic Algorithm Validation Program (CAVP) GCM test vectors.

```
Key:       0000000000000000000000000000000000000000000000000000000000000000
Nonce:     000000000000000000000000
Plaintext: (empty)
AAD:       (empty)
CT:        (empty)
Tag:       530f8afbc74536b9a963b4f1c4cb738b
```

The tag is the GCM authentication code computed over an empty message and empty
AAD with an all-zero 256-bit key and 96-bit IV.

---

## 2. GF(2⁸) Arithmetic Vectors

The Galois field uses primitive polynomial
$p(x) = x^8 + x^4 + x^3 + x^2 + 1$ (`0x11d`).

### GF-01 — Multiplication identity

```
gf_mul(a, 1) = a     for all a ∈ GF(256)
```

Spot checks:
```
gf_mul(0x53, 0x01) = 0x53
gf_mul(0xCA, 0x01) = 0xCA
gf_mul(0x00, 0x01) = 0x00
```

### GF-02 — Multiplicative inverse

Any non-zero element satisfies `a * inv(a) = 1`:

```
gf_mul(0x53, gf_inv(0x53)) = 0x01
gf_mul(0x03, gf_inv(0x03)) = 0x01
```

These can be independently verified using the Euclidean algorithm over GF(2)[x].

### GF-03 — Known multiplication result

In the field defined above:

```
gf_mul(0x53, 0x02) = 0xA6    (left shift: 01010011 → 10100110, no reduction)
gf_mul(0xD4, 0x02) = 0xB5    (left shift 0xA8 XOR carry byte 0x1D)
```

Derivation of `gf_mul(0x53, 0x02)`:  
`0x53 = 0101 0011`. MSB = 0, so multiply by 2 = left-shift = `1010 0110 = 0xA6`. No polynomial reduction needed.

---

## 3. Shamir Secret Sharing Vectors

### SSS-01 — Deterministic reconstruction from known shares

The following shares were computed analytically from the polynomial:

$$f(x) = 0\text{x}42 + 0\text{x}53 \cdot x \quad \text{over } \text{GF}(2^8)$$

```
Secret:    0x42
Threshold: 2 of 2

Share 1 (x=1):   f(1) = 0x42 XOR 0x53 = 0x11
Share 2 (x=2):   f(2) = 0x42 XOR gf_mul(0x53, 2) = 0x42 XOR 0xA6 = 0xE4

Reconstruction:  ShamirReconstruct([{1, 0x11}, {2, 0xE4}]) = [0x42]
```

Verify manually:
- `0x42 XOR 0x53 = 0x11` ✓ (bit-by-bit XOR of 01000010 and 01010011)
- `gf_mul(0x53, 2) = 0xA6` ✓ (MSB of 0x53 is 0, left-shift only)
- `0x42 XOR 0xA6 = 0xE4` ✓ (01000010 XOR 10100110 = 11100100)

The test in `test_vectors.rs` verifies this reconstruction using the public
`reconstruct_secret` API.

### SSS-02 — Too-few-shares leaves the secret undetermined

Given fewer than the threshold number of shares, every candidate secret remains
equally likely in the ideal scheme. Interpolating only the observed points still
returns a byte string, but it is only one candidate; it is not an authenticated
reconstruction. That candidate can equal the real value by chance (probability
`1/256` for one byte and `256^-32` for an independently split 32-byte key), so a
valid test must not assert that under-threshold output is *always* different.

---

## 4. Container Round-Trip Vector

### CTR-01 — Serialise / Deserialise identity

A container produced by `encrypt_bytes(b"hello quantum vault")` must satisfy:

```
QuantumVaultContainer::from_bytes(container.to_bytes()) == Ok(same container)
```

This is a structural/determinism test, not a static vector.

---

## 5. Full Pipeline Vectors

### FP-01 — Round-trip correctness (property-based)

```
for any plaintext P and threshold t:
  (container, keys, sig_pub) ← encrypt_with_threshold(P, n, t)
  recovered = decrypt_with_threshold(container, keys[:t], sig_pub)
  assert recovered == P
```

### FP-02 — Nonce freshness

Two calls to `encrypt_bytes` with the same plaintext MUST produce different
containers (different nonces → different ciphertexts) with overwhelming
probability.

---

## 6. How to Generate and Verify Vectors Independently

### AES vectors

Compare against the NIST CAVP response files or use an independent AES-GCM API.
For example, Node's Web Crypto implementation returns ciphertext followed by the
tag and therefore prints the expected 16-byte value for the empty message:

```bash
node --input-type=module -e '
  const key = await crypto.subtle.importKey(
    "raw", new Uint8Array(32), "AES-GCM", false, ["encrypt"]);
  const out = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: new Uint8Array(12), tagLength: 128 },
    key, new Uint8Array());
  console.log(Buffer.from(out).toString("hex"));
'
# 530f8afbc74536b9a963b4f1c4cb738b
```

`openssl enc` is not an alternative for this check: current OpenSSL releases do
not expose AEAD modes such as GCM through the `enc` command.

### Shamir vectors

The Sage mathematics system can verify GF(256) arithmetic:

```python
F.<x> = GF(2^8, modulus=x^8+x^4+x^3+x^2+1)
a = F.fetch_int(0x53)
b = F.fetch_int(0x02)
print(hex((a*b).integer_representation()))   # should print 0xa6
```

### Rust implementation

Run the vector generator (prints hex for external verification):

```bash
cargo test -p qv-core generate_test_vectors -- --ignored --nocapture
```

---

## 7. Regression Policy

When the implementation changes in a way that affects cryptographic outputs:

1. Run the generator tests to produce new vectors.
2. Verify the new vectors against a reference implementation or independent
   computation.
3. Update the hardcoded expected values in `test_vectors.rs`.
4. Update this document.
5. Document the reason for the change in the commit message.

Any change to `AES vector AES-01` (a NIST vector) indicates a regression.
