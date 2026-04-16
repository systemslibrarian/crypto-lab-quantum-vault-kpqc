# Crypto Decisions — Fast Reference

> **If you follow this, you will not make cryptography mistakes.**

This is the decision engine for the Quantum Vault KPQC platform.
Every recommendation is opinionated, defensible, and tied to real-world usage.

---

## ⚡ Fast Decision Rules

| If you need to…                        | Use this                        | NOT this                          |
|----------------------------------------|---------------------------------|-----------------------------------|
| Encrypt data at rest                   | **AES-256-GCM**                 | AES-CBC, AES-ECB, ChaCha20 alone  |
| Store passwords                        | **Argon2id** (or PBKDF2 ≥600k) | SHA-256, bcrypt, MD5              |
| Split a secret among $n$ parties       | **Shamir SSS over GF(2⁸)**     | XOR splitting, naive modular SSS  |
| Exchange keys (quantum-resistant)      | **SMAUG-T KEM** / ML-KEM       | Raw RSA, static DH                |
| Sign data (quantum-resistant)          | **HAETAE** / ML-DSA             | RSA-PKCS1v1.5, raw ECDSA         |
| Authenticate encrypted data            | **AEAD (GCM/CCM)** or Encrypt-then-MAC | Encrypt-and-MAC, MAC-then-Encrypt |
| Protect against quantum computers      | **Hybrid: classical + PQ KEM**  | Classical-only RSA/ECDH           |
| Generate random numbers                | **OS CSPRNG** (`OsRng`, `crypto.getRandomValues`) | `Math.random()`, `rand()` |

**When unsure → AES-256-GCM + Argon2id + ML-KEM. These are safe defaults.**

---

## 🗺️ Layer 1 — Algorithm Comparison (Decision Engine)

### AES-256-GCM — Authenticated Symmetric Encryption

Encrypts and authenticates data with a single key. The gold standard.

- **✅ Best for:** Encrypting files, database fields, API payloads, anything at rest or in transit
- **❌ Avoid if:** You need to encrypt with a public key (use hybrid KEM + AES instead)
- **⚖️ Tradeoffs:** Hardware-accelerated on all modern CPUs (AES-NI). 12-byte nonce MUST be unique per key — reuse destroys confidentiality AND authenticity
- **🔥 Complexity:** Low — one function call in every crypto library
- **🌍 Real-world:** TLS 1.3, disk encryption, every cloud KMS
- **🔗 Demo:** Quantum Vault deposit (encrypt) and retrieve (decrypt)

#### Why AES-GCM instead of AES-CBC?

AES-CBC provides no integrity. An attacker can flip ciphertext bits and produce
controlled changes in plaintext (padding oracle attacks). AES-GCM detects any
tampering. **There is no reason to use CBC for new systems.**

#### What breaks if you choose wrong?

| Mistake | Consequence |
|---------|-------------|
| Nonce reuse | Attacker recovers XOR of plaintexts + authentication key |
| AES-ECB | Identical blocks → identical ciphertext (leaks patterns) |
| No authentication | Attacker modifies ciphertext undetected |

---

### Shamir Secret Sharing (SSS) — Threshold Key Splitting

Splits a secret into $n$ shares where any $t$ shares reconstruct it, but $t-1$ shares reveal *nothing*.

- **✅ Best for:** Multi-party key custody, backup recovery, dead man's switches, M-of-N approval
- **❌ Avoid if:** You need to *compute* on shares without reconstruction (use MPC instead)
- **⚖️ Tradeoffs:** Information-theoretically secure (not broken by quantum computers). But shares must be kept confidential — SSS protects the secret, not the shares
- **🔥 Complexity:** Medium — correct GF arithmetic is critical; bugs silently produce wrong results
- **🌍 Real-world:** HashiCorp Vault unseal keys, cryptocurrency wallet recovery, enterprise key escrow
- **🔗 Demo:** Quantum Vault splits every AES key into 3 shares (threshold 2)

#### Why Shamir instead of XOR splitting?

XOR splitting requires ALL shares to reconstruct. Lose one share → lose everything.
Shamir lets you set any threshold $t ≤ n$: flexible, fault-tolerant.

#### What breaks if you choose wrong?

| Mistake | Consequence |
|---------|-------------|
| Threshold = 1 | Any single share reconstructs the secret (no security) |
| Wrong GF polynomial | Silent data corruption — reconstruction produces garbage |
| Shares not wiped after use | Leaked shares reduce effective threshold |

---

### SMAUG-T — Post-Quantum Key Encapsulation Mechanism (KEM)

Lets a sender create a shared secret with a recipient using only their public key. Quantum-resistant.

- **✅ Best for:** Key exchange, hybrid encryption (KEM + AES-GCM), any key transport
- **❌ Avoid if:** You only need symmetric encryption (AES-GCM alone is simpler). Not for signatures
- **⚖️ Tradeoffs:** Larger keys than RSA/ECDH (672B PK at Level 1). Lattice-based — newer than RSA but under heavy research scrutiny. Part of the Korean KpqC competition (comparable to NIST ML-KEM)
- **🔥 Complexity:** Medium — use the KEM API (encapsulate/decapsulate), never build your own
- **🌍 Real-world:** Post-quantum TLS (hybrid mode in Chrome/Firefox), secure messaging (Signal PQ), government systems preparing for Q-Day
- **🔗 Demo:** Quantum Vault wraps each Shamir share with a fresh SMAUG-T KEM

#### Why KEM instead of raw public-key encryption?

KEMs produce a fixed-size shared secret; you then use it as an AES key. This avoids
padding attacks, ciphertext malleability, and the "encrypt arbitrary data with RSA" anti-pattern.
**Do NOT encrypt data directly with a public key. Ever.**

#### What breaks if you choose wrong?

| Mistake | Consequence |
|---------|-------------|
| Raw RSA encryption | Padding oracle attacks, ciphertext malleability |
| Classical-only DH | Vulnerable to Shor's algorithm on quantum computers |
| Reusing KEM keypair across contexts | Cross-protocol attacks; generate fresh keypairs |

---

### HAETAE — Post-Quantum Digital Signatures

Proves that data was created by the holder of a private key and has not been modified. Quantum-resistant.

- **✅ Best for:** Code signing, container authentication, certificate issuance, document notarization
- **❌ Avoid if:** You need encryption (signatures don't provide confidentiality). Not for key exchange
- **⚖️ Tradeoffs:** Signature size up to 1474B (Mode 2) — larger than Ed25519 (64B) but quantum-safe. Verification is fast; signing is slower
- **🔥 Complexity:** Medium — verify FIRST, then process. Never process data before verifying the signature
- **🌍 Real-world:** Post-quantum code signing (Windows, Linux package managers), document integrity in government systems
- **🔗 Demo:** Quantum Vault signs every sealed container with HAETAE before storage

#### Why verify-first?

If you decrypt before verifying, an attacker can feed you tampered ciphertext and observe
your system's behavior (error messages, timing) to learn about the plaintext. This is how
padding oracles work. **Always verify, then decrypt.**

#### What breaks if you choose wrong?

| Mistake | Consequence |
|---------|-------------|
| Skip verification | Attacker substitutes containers, shares, or ciphertext |
| Verify after decrypt | Padding oracle / chosen-ciphertext attacks |
| RSA-PKCS1v1.5 signatures | Bleichenbacher-style forgery attacks |

---

## 💥 Failure Simulations (What Happens When You Get It Wrong)

### Failure 1: Insufficient Shamir Shares

**Scenario:** Attacker has 1 of 3 shares (threshold = 2).

**What happens:** Lagrange interpolation with 1 share produces completely random bytes.
The AES-GCM decryption fails (tag mismatch) or produces gibberish — there is no
partial information leak.

**Why it matters:** This is information-theoretic security. Not "hard to break" — literally
*impossible* to extract any information about the secret from fewer than $t$ shares,
even with unlimited compute.

**Demo:** In Quantum Vault, enter only 1 of 2 required passwords. The pipeline animation
stops at "Shamir Reconstruct" with a failure indicator, and the decrypt output shows
scrambled nonsense from the actual wrong Lagrange interpolation.

---

### Failure 2: Wrong Password → Wrong SMAUG-T Secret Key

**Scenario:** User enters an incorrect password for a share.

**What happens:** PBKDF2 derives a wrong key → AES-GCM decryption of the SMAUG-T
secret key fails (authentication tag mismatch) → `unwrapShare()` throws immediately.
The share is not counted toward the threshold.

**Why it matters:** Password errors are detected instantly (authenticated encryption),
not silently (which would produce a corrupted secret key that might cause subtle
downstream failures).

---

### Failure 3: Tampered Container → Signature Rejection

**Scenario:** Attacker modifies any byte of the sealed container.

**What happens:** `haetaeVerify()` returns false → `openBox()` rejects the container
*before* any KEM or AES operation runs. Zero information about the plaintext leaks.

**Why it matters:** Verify-first design prevents chosen-ciphertext attacks. The attacker
cannot observe decrypt behavior to learn about the plaintext.

---

## 🎓 Layer 3 — Learning Path

### Beginner (Start Here)

1. **What is encryption?** — AES-256-GCM demo: deposit a message, retrieve it with the right password
2. **What is key splitting?** — Shamir SSS demo: need 2 of 3 passwords to open a box
3. **What is a nonce?** — Why every encryption uses a fresh random value (and what breaks if you don't)

**Prerequisites:** None. Just a browser.

### Intermediate

4. **What is a KEM?** — SMAUG-T wraps each share with public-key crypto
5. **What are digital signatures?** — HAETAE signs every container (verify-first principle)
6. **What is a threshold scheme?** — A policy that survives individual key loss

**Prerequisites:** Beginner path. Understanding of "encrypt with key" concept.

### Advanced

7. **Post-quantum cryptography** — Why lattice-based crypto. SMAUG-T vs ML-KEM. HAETAE vs ML-DSA
8. **Container format design** — AAD, signing corpus, algorithm identifiers as authenticated data
9. **Cross-platform crypto** — Same algorithms in browser WASM and Rust CLI with different security levels

**Prerequisites:** Intermediate path. Comfort with public-key concepts.

---

## ⚠️ Credibility & Disclaimers

### Threat Model Summary

| Attacker | Defended? |
|----------|-----------|
| Passive network observer | ✅ Yes — IND-CPA of SMAUG-T + AES-256-GCM |
| $t-1$ colluding insiders | ✅ Yes — information-theoretic SSS security |
| Storage/backup compromise | ✅ Yes — fewer than $t$ shares reveal nothing |
| Active container tampering | ✅ Yes — HAETAE signature covers all fields |
| Quantum computer (HNDL) | ✅ Yes — SMAUG-T and HAETAE are post-quantum |
| Algorithm substitution | ✅ Yes — algorithm IDs are in AAD / signing corpus |

### What is NOT Protected

- **Side channels in WASM:** Browser JS/WASM timing is not constant-time. This is educational software.
- **Key management:** The demo stores keys in `localStorage`. Production systems need HSMs or secure enclaves.
- **Password strength:** The system cannot enforce strong passwords. Weak passwords undermine PBKDF2.
- **Browser compromise:** If the browser is compromised (XSS, malicious extension), all bets are off.

### Disclaimers

- ⚠️ **Educational only.** Do not use for production data protection.
- ⚠️ **Not audited.** The C reference implementations have not undergone formal security audit.
- ⚠️ **Not production-ready.** No HSM integration, no key rotation, no access logging.

### References

| Standard | Relevance |
|----------|-----------|
| NIST SP 800-38D | AES-GCM specification |
| NIST SP 800-132 | PBKDF2 recommendation (≥600k iterations for SHA-256) |
| NIST FIPS 203 (ML-KEM) | Post-quantum KEM standard (SMAUG-T is the Korean equivalent) |
| NIST FIPS 204 (ML-DSA) | Post-quantum signature standard (HAETAE is the Korean equivalent) |
| Shamir, "How to Share a Secret" (1979) | Original SSS paper |
| KpqC Competition | Korean post-quantum crypto standardization (source of SMAUG-T + HAETAE) |

---

## 🧪 Self-Evaluation

| Criterion | Score |
|-----------|-------|
| Clarity | 9/10 — Plain English first, math layered in |
| Decision usefulness | 9/10 — Fast rules table + per-algorithm "why this, not that" |
| Real-world relevance | 9/10 — Every algorithm tied to TLS, key management, real threats |
| Cognitive load | 8/10 — Structured progression, but advanced section could be deeper |
| Credibility | 9/10 — Threat model, disclaimers, and NIST/RFC references included |

**Weakness:** The learning path references demo interactions that don't yet have standalone guided walkthroughs. Future work: add step-by-step tutorial mode to the web demo.

---

*"So whether you eat or drink or whatever you do,
do it all for the glory of God." — 1 Corinthians 10:31*
