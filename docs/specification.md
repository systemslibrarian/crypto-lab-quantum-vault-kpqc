# Quantum Vault — Formal Cryptographic Specification

**Version:** 1.0  
**Date:** 2026-03  
**Status:** Stable

---

## 1. Introduction

Quantum Vault is a *threshold* encryption platform: a file can be encrypted such
that at least *t* out of *n* designated recipients must cooperate to decrypt it.
The key-encapsulation layer uses post-quantum algorithms (SMAUG-T, HAETAE) from
the Korean Post-Quantum Cryptography (KpqC) competition, ensuring confidentiality
against both classical and quantum adversaries.

This document is the normative specification of the cryptographic protocol.
Implementations must produce outputs indistinguishable from those described here.

---

## 2. Notation

| Symbol | Meaning |
|--------|---------|
| $n$ | Total number of recipients (shares) |
| $t$ | Reconstruction threshold ($2 \le t \le n$) |
| $F$ | Plaintext file (arbitrary byte string) |
| $K$ | 256-bit AES file key |
| $\text{KEM}$ | Key Encapsulation Mechanism |
| $\text{SIG}$ | Digital Signature Scheme |
| $\oplus$ | XOR |
| $\text{GF}(2^8)$ | Galois field of 256 elements |
| $\text{SHA-256}$ | SHA-2 hash with 256-bit output |

---

## 3. System Model

### 3.1 Participants

```
Encryptor        — generates ephemeral keypairs, produces the container
Recipient_i      — holds (pk_i, sk_i) for i ∈ {1..n}
Verifier         — holds the encryptor's signature public key sig_pk
```

### 3.2 Protocol Parameters

| Parameter | Value | Reference |
|-----------|-------|-----------|
| KEM | SMAUG-T Level 1 | KpqC Round 1 |
| Signature | HAETAE Mode 2 | KpqC Round 1 |
| Symmetric cipher | AES-256-GCM | NIST SP 800-38D |
| Secret sharing | Shamir over GF(2⁸) | Shamir 1979 |
| Container format | JSON v1 | docs/container-format.md |
| Share wrapping | AES-256-GCM (aead_protect) | §6.3 |

### 3.3 Key Sizes

| Algorithm | Public key | Private key | Ciphertext / Signature |
|-----------|-----------|-------------|------------------------|
| SMAUG-T Level 1 | 672 B | 832 B | CT: 672 B, SS: 32 B |
| HAETAE Mode 2   | 992 B | 1 408 B | ≤ 1 474 B |
| AES-256-GCM | — | 32 B | plaintext + 16 B tag |

---

## 4. Encryption Algorithm

### 4.1 Inputs

```
plaintext F          (arbitrary bytes)
recipient_pks        [pk_1, pk_2, ..., pk_n]   (KEM public keys)
signer_sk            sig_sk                     (signature private key)
threshold t, count n
```

### 4.2 Steps

**Step 1 — Generate a random file key:**

$$K \xleftarrow{\$} \{0,1\}^{256}$$

**Step 2 — Generate a random nonce:**

$$\text{nonce} \xleftarrow{\$} \{0,1\}^{96}$$

**Step 3 — Encrypt the plaintext with AES-256-GCM:**

$$C \leftarrow \text{AES-256-GCM}_{K}(\text{nonce},\ F,\ \text{AAD})$$

where the Additional Authenticated Data is (see §6.1):

$$\text{AAD} = \text{JSON}\!\left\{\text{"kem\_algorithm"}, \text{"sig\_algorithm"}, \text{"threshold"}, \text{"version"}\right\}$$

Keys are sorted alphabetically to ensure deterministic serialisation.

**Step 4 — Shamir-split the file key:**

$$[S_1, \ldots, S_n] \leftarrow \text{ShamirSplit}(K,\ n,\ t)$$

Each $S_i = (i,\ \mathbf{y}_i)$ where $\mathbf{y}_i \in \text{GF}(2^8)^{32}$
is the evaluation of the per-byte polynomials at $x = i$.

**Step 5 — KEM-protect each share:**

For each $i \in [1..n]$:

$$(\text{kem\_ct}_i,\ \text{ss}_i) \leftarrow \text{KEM.Encapsulate}(pk_i)$$

$$E_i \leftarrow \text{AeadProtect}(S_i.\text{data},\ \text{ss}_i)$$

$$\text{ss}_i \xleftarrow{\text{zeroize}} \bot$$

**Step 6 — Serialize and sign the container:**

Produce the canonical byte string $M_\text{canon}$ (see §6.2) covering all
fields *except* the signature itself, then:

$$\sigma \leftarrow \text{SIG.Sign}(\text{sig\_sk},\ M_\text{canon})$$

**Step 7 — Assemble and output the container.**

### 4.3 Pseudocode

```
function Encrypt(F, pks, sig_sk, n, t):
  K   ← random(32)
  IV  ← random(12)
  AAD ← serialize_aad(version, t, kem_alg, sig_alg)
  C   ← AES_GCM_Encrypt(K, IV, F, AAD)
  shares ← ShamirSplit(K, n, t)
  zeroize(K)

  encrypted_shares ← []
  for i in 1..n:
    (ct_i, ss_i) ← KEM.Encapsulate(pks[i-1])
    E_i          ← AeadProtect(shares[i].data, ss_i)
    zeroize(ss_i)
    encrypted_shares.append({index: i, kem_ciphertext: ct_i, encrypted_share: E_i})

  container ← {version, cipher, kem_alg, sig_alg, t, n, IV, C, encrypted_shares, sig: ∅}
  M         ← canonical_bytes(container)
  container.sig ← SIG.Sign(sig_sk, M)
  return container
```

---

## 5. Decryption Algorithm

### 5.1 Inputs

```
container            JSON v1 container
privkeys             [sk_{i1}, ..., sk_{im}]   (m ≥ t KEM private keys)
share_indices        [i1, ..., im]              (indices in container.shares)
sig_pk               signature verification key
```

### 5.2 Steps

**Step 1 — Verify the container signature (before touching any ciphertext):**

$$\text{valid} \leftarrow \text{SIG.Verify}(\text{sig\_pk},\ M_\text{canon},\ \sigma)$$

Abort if not valid.

**Step 2 — Recover each share:**

For each supplied $(sk_{ij},\ i_j)$:

$$\text{ss}_{ij} \leftarrow \text{KEM.Decapsulate}(sk_{ij},\ \text{kem\_ct}_{ij})$$

$$S_{ij} \leftarrow \text{AeadProtect}^{-1}(E_{ij},\ \text{ss}_{ij})$$

$$\text{ss}_{ij} \xleftarrow{\text{zeroize}} \bot$$

**Step 3 — Reconstruct the file key:**

$$K \leftarrow \text{ShamirReconstruct}([S_{i1}, \ldots, S_{im}])$$

**Step 4 — Decrypt the ciphertext:**

$$F \leftarrow \text{AES-256-GCM-Decrypt}(K,\ \text{nonce},\ C,\ \text{AAD})$$

$$K \xleftarrow{\text{zeroize}} \bot$$

Return $F$. Abort if AES authentication tag verification fails.

---

## 6. Sub-Algorithm Specifications

### 6.1 AAD Construction

The AAD binds the ciphertext to its algorithmic and policy context, preventing
algorithm-substitution and downgrade attacks:

```json
{
  "kem_algorithm":  "<string>",
  "sig_algorithm":  "<string>",
  "threshold":      <uint8>,
  "version":        <uint8>
}
```

JSON keys are sorted alphabetically; the AAD is the canonical UTF-8 JSON bytes.

### 6.2 Signing Canonical Byte String

The signed corpus is the UTF-8 encoding of a JSON object with **keys sorted
alphabetically at every level** and byte arrays base64-encoded.  The
`signature` field is excluded.  Using field names as delimiters rather than
raw byte concatenation makes the encoding injective — no two distinct
containers can produce the same byte string.

**Web demo (TypeScript) corpus:**

```json
{
  "ciphertext":    "<base64>",
  "createdAt":     "<ISO 8601 timestamp>",
  "nonce":         "<base64>",
  "sigPublicKey":  "<base64>",
  "wrappedShares": [
    {
      "iterations":      <uint32>,
      "kemCiphertext":   "<base64>",
      "publicKey":       "<base64>",
      "salt":            "<base64>",
      "shareNonce":      "<base64>",
      "skNonce":         "<base64>",
      "wrappedSecretKey":"<base64>",
      "wrappedShare":    "<base64>"
    }
  ]
}
```

**Rust core (qv-core) corpus:**

```json
{
  "ciphertext":     [<bytes>],
  "cipher":         "Aes256Gcm",
  "kem_algorithm":  "<string>",
  "magic":          "QVLT1",
  "nonce":          [<bytes>],
  "share_count":    <uint8>,
  "shares":         [{...}],
  "sig_algorithm":  "<string>",
  "threshold":      <uint8>,
  "version":        <uint8>
}
```

Both implementations sort keys alphabetically and sign the UTF-8 JSON bytes.
The field sets differ because the two implementations use different container
formats (see §3.2); they are not cross-compatible at the container level.

### 6.3 AeadProtect Share Wrapping

Each Shamir share is wrapped with AES-256-GCM using the KEM shared secret as
the encryption key:

```
function AeadProtect(share_data, kem_shared_secret):
  key   ← kem_shared_secret          # 32 bytes
  nonce ← random(12)                 # 96-bit IV (stored in container)
  E     ← AES-256-GCM-Encrypt(key, nonce, share_data, AAD="")
  return (nonce, E)                  # E includes the 16-byte auth tag

function AeadProtect⁻¹(nonce, E, kem_shared_secret):
  key ← kem_shared_secret
  return AES-256-GCM-Decrypt(key, nonce, E, AAD="")  # aborts if tag invalid
```

Authentication tag verification provides integrity and prevents an attacker
who corrupts a share ciphertext from learning anything about the share content.
The KEM shared secret is zeroized immediately after wrapping/unwrapping.

### 6.4 Shamir Secret Sharing over GF(2⁸)

**Field specification:**  
$\text{GF}(2^8)$ with irreducible polynomial $p(x) = x^8 + x^4 + x^3 + x^2 + 1$
(hexadecimal representation: `0x11d`).

> **Note:** The AES field polynomial $x^8 + x^4 + x^3 + x + 1$ (`0x11b`) is
> irreducible but the element $2$ has multiplicative order 51 in that field, not
> 255. Using it with a generator-2 EXP/LOG table silently corrupts the table;
> `0x11d` is used here because 2 is a primitive element of order 255.

**Split:**  
For each byte $b$ of the secret, sample a random polynomial of degree $t-1$:

$$f_b(x) = b + a_1 x + a_2 x^2 + \cdots + a_{t-1} x^{t-1} \in \text{GF}(2^8)[x]$$

with $a_j \xleftarrow{\$} \text{GF}(2^8)^*$ (rejection-sampled to avoid zero).  
Share $i$ receives the evaluation $f_b(i)$ for $i = 1, \ldots, n$.

**Reconstruct:**  
Use Lagrange interpolation at $x = 0$:

$$b = \sum_{j=1}^{m} f_b(x_j) \prod_{k \ne j} \frac{x_k}{x_j \oplus x_k}$$

where all arithmetic is in $\text{GF}(2^8)$.

---

## 7. Security Properties

### 7.1 Confidentiality

The file key $K$ is computationally indistinguishable from random given fewer
than $t$ encrypted shares, under the IND-CPA security of SMAUG-T and the
information-theoretic security of Shamir Secret Sharing.

### 7.2 Integrity

An adversary who modifies *any* field in the container (including the nonce,
ciphertext, or shares) will cause the HAETAE signature verification (Step 1 of
decryption) to fail with overwhelming probability, under the EUF-CMA security
of HAETAE.

### 7.3 Authenticity

The container binds the signer identity to the specific algorithm choices,
threshold policy, and all key-share ciphertexts. A substitution of even a
single KEM ciphertext is detectable.

### 7.4 Post-Quantum Resistance

Both SMAUG-T (KEM) and HAETAE (signature) are based on lattice hardness
assumptions (MLWE, MLWR, MSIS) believed to resist quantum attacks. The
symmetric-key component (AES-256-GCM) provides 128 bits of post-quantum
security against Grover's algorithm.

### 7.5 Perfect Threshold Security

The Shamir scheme over $\text{GF}(2^8)$ is information-theoretically secure:
any subset of fewer than $t$ shares reveals *zero* information about $K$,
regardless of the adversary's computational power.

---

## 8. Implementation Notes

- The file key $K$ and all intermediate keying material must be zeroized from
  memory after use (using the `zeroize` crate).
- Signature verification must occur *before* any decryption operation to
  prevent oracle attacks.
- The `dev-backend` uses SHA-256/XOR stubs and is **not secure**; it exists
  only for tests and local development.
- Container parsing enforces strict structural validation before any
  cryptographic operation begins (see `container.rs::from_bytes`).

---

## References

1. Amos Shamir. "How to Share a Secret." CACM 22(11), 1979.
2. NIST SP 800-38D. Recommendation for Block Cipher Modes of Operation:
   Galois/Counter Mode (GCM). 2007.
3. KpqC Competition. "SMAUG-T Specification v1.1," 2024.
4. KpqC Competition. "HAETAE Specification v1.1," 2024.
5. NIST FIPS 197. Advanced Encryption Standard (AES). 2001.
6. Mihir Bellare, Phillip Rogaway. "Entity Authentication and Key Distribution."
   CRYPTO 1993. (IND-CCA2 KEM definition)
