# Crypto Decisions — Fast Reference

> Educational decision guide, not a substitute for a reviewed protocol,
> production threat model, or independently audited implementation.

This is the decision engine for the Quantum Vault KPQC platform.
Every recommendation is opinionated, defensible, and tied to real-world usage.

---

## ⚡ Fast Decision Rules

| If you need to…                        | Use this                        | NOT this                          |
|----------------------------------------|---------------------------------|-----------------------------------|
| Encrypt data at rest                   | **AES-256-GCM**                 | AES-CBC, AES-ECB, ChaCha20 alone  |
| Store passwords                        | **Argon2id**; PBKDF2-HMAC-SHA-256 ≥600k when FIPS compatibility is required | Fast hashes such as raw SHA-256 or MD5 |
| Split a secret among $n$ parties       | **Shamir SSS over GF(2⁸)**     | XOR splitting, naive modular SSS  |
| Exchange keys with a published PQ standard | **ML-KEM**, normally in an approved hybrid construction | An experimental algorithm selected only because a demo uses it |
| Sign with a published PQ standard      | **ML-DSA**                      | An experimental algorithm selected only because a demo uses it |
| Authenticate encrypted data            | **AEAD (GCM/CCM)** or Encrypt-then-MAC | Encrypt-and-MAC, MAC-then-Encrypt |
| Protect against quantum computers      | **Hybrid: classical + PQ KEM**  | Classical-only RSA/ECDH           |
| Generate random numbers                | **OS CSPRNG** (`OsRng`, `crypto.getRandomValues`) | `Math.random()`, `rand()` |

Algorithm names alone are not safe defaults: use a maintained library and a
reviewed protocol with nonce management, key lifecycle, authentication and
deployment requirements defined for the application.

---

## 🗺️ Layer 1 — Algorithm Comparison (Decision Engine)

### AES-256-GCM — Authenticated Symmetric Encryption

Encrypts and authenticates data with a single key when its nonce and key
lifecycle requirements are enforced.

- **✅ Best for:** Encrypting files, database fields, API payloads, anything at rest or in transit
- **❌ Avoid if:** You need to encrypt with a public key (use hybrid KEM + AES instead)
- **⚖️ Tradeoffs:** Common platforms provide hardware acceleration. A 12-byte nonce MUST be unique per key — reuse destroys confidentiality AND authenticity
- **🔥 Complexity:** Low — one function call in every crypto library
- **🌍 Real-world:** TLS 1.3 cipher suites, storage encryption and envelope-encryption systems
- **🔗 Demo:** Quantum Vault deposit (encrypt) and retrieve (decrypt)

#### Why AES-GCM instead of AES-CBC?

AES-CBC provides no integrity. An attacker can flip ciphertext bits and produce
controlled changes in plaintext unless a separate, correctly ordered
authentication mechanism is used. New designs should normally choose a
well-supported AEAD rather than compose CBC and authentication themselves.

#### What breaks if you choose wrong?

| Mistake | Consequence |
|---------|-------------|
| Nonce reuse | Repeated keystream leaks plaintext relations and enables practical forgery attacks |
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

Lets a sender create a shared secret with a recipient using only their public
key. SMAUG-T is designed against known classical and quantum attacks, but its
KpqC competition selection is not publication as a Korean Standard.

- **✅ Best for:** Studying the KpqC candidate and this lab's KEM + AEAD construction
- **❌ Avoid if:** You only need symmetric encryption (AES-GCM alone is simpler). Not for signatures
- **⚖️ Tradeoffs:** Larger keys than common classical schemes (672-byte public key at Level 1). It is a final KpqC competition algorithm proposed for Korean-standard development, not an interchangeable or published equivalent of ML-KEM
- **🔥 Complexity:** Medium — use the KEM API (encapsulate/decapsulate), never build your own
- **🌍 Status:** Research, interoperability testing and Korean-standardization work; this repository does not establish production adoption
- **🔗 Demo:** Quantum Vault wraps each Shamir share with a fresh SMAUG-T KEM

#### Why KEM instead of raw public-key encryption?

KEMs produce a fixed-size shared secret; you then use it as an AES key. This avoids
the fragile "encrypt arbitrary data with textbook RSA" pattern. Use the KEM and
key-derivation construction specified by the protocol rather than inventing one.

#### What breaks if you choose wrong?

| Mistake | Consequence |
|---------|-------------|
| Raw RSA encryption | Padding oracle attacks, ciphertext malleability |
| Classical-only DH | Vulnerable to Shor's algorithm on quantum computers |
| Reusing KEM keypair across contexts | Cross-protocol attacks; generate fresh keypairs |

---

### HAETAE — Post-Quantum Digital Signatures

With an independently authenticated public key, proves that data was signed by
the corresponding private-key holder and has not been modified. The browser
demo verifies under a replaceable key embedded in the same container, so it
demonstrates tamper detection for an unchanged container but not original-sender
authentication.

- **✅ Best for:** Studying the KpqC signature candidate and authenticated-key signature workflows
- **❌ Avoid if:** You need encryption (signatures don't provide confidentiality). Not for key exchange
- **⚖️ Tradeoffs:** Signature size up to 1474B (Mode 2) — larger than Ed25519 (64B). HAETAE is designed against known quantum attacks but remains under Korean-standardization review
- **🔥 Complexity:** Medium — verify FIRST, then process. Never process data before verifying the signature
- **🌍 Status:** Competition/reference implementation and standardization review; this repository does not establish deployment by operating-system package ecosystems
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

**What happens:** Lagrange interpolation with one share produces one candidate
byte string. Conditioned on the observed share, the real secret remains uniform
over all candidates in the ideal scheme, so each candidate byte can coincide
with the real byte with probability `1/256`. The candidate is not authenticated;
AES-GCM normally rejects it at the tag check.

**Why it matters:** This is information-theoretic security. Not "hard to break" — literally
*impossible* to extract any information about the secret from fewer than $t$ shares,
even with unlimited compute.

**Demo:** In Quantum Vault, enter only one of two required passwords. The core
tries AES-GCM authentication with the real Lagrange candidate. After that fails,
the UI animation marks "Shamir Reconstruct" as a warning and does not animate
the AES step. The key strip can show the real candidate; the ACCESS DENIED
gibberish is independently generated random display data, not secret material.

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

**Scenario:** Attacker modifies a signed field of the sealed container.

**What happens:** A byte change made without replacing the embedded key and
re-signing makes `haetaeVerify()` return false, so `openBox()` rejects before
any KEM or AES operation runs. No plaintext is returned on that path.

**Why it matters:** Verify-first design avoids exposing the KEM/decrypt path to
containers that fail under the selected verification key. Because that key is
embedded and unpinned, this is tamper demonstration—not original-sender
authentication or a complete chosen-ciphertext security argument.

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
9. **Cross-platform architecture** — Compare the active browser WASM path with the Rust native-FFI design and its currently unimplemented WASM scaffold

**Prerequisites:** Intermediate path. Comfort with public-key concepts.

---

## ⚠️ Credibility & Disclaimers

### Threat Model Summary

| Threat | Demonstrated boundary |
|--------|-----------------------|
| Passive observation | Ciphertext confidentiality depends on the stated SMAUG-T and AES-GCM assumptions and correct implementation |
| Fewer than $t$ valid Shamir shares | The ideal SSS construction reveals no secret information; password quality and endpoint compromise remain separate |
| Storage/backup compromise | Wrapped shares require passwords, but weak passwords remain vulnerable to offline guessing |
| Active byte tampering | Rejected under the container's included verification key; wholesale key replacement is not original-sender authentication |
| Harvest-now/decrypt-later | Uses algorithms designed for post-quantum security; the demo is not a security proof or production assurance |
| Algorithm substitution | IDs are signed/AAD-bound, subject to the same unpinned-key and implementation boundaries |

### What is NOT Protected

- **Side channels in WASM:** Constant-time behavior has not been established for
  the active browser artifacts. This is educational software.
- **Key management:** `localStorage` holds encrypted SMAUG-T secret keys inside
  sealed containers. Plaintext key material is transiently present across JS
  typed arrays, WASM memory and Web Crypto internals; no HSM or secure enclave
  protects it.
- **Password strength:** The system cannot enforce strong passwords. Weak passwords undermine PBKDF2.
- **Browser compromise:** If the browser is compromised (XSS, malicious extension), all bets are off.

### Disclaimers

- ⚠️ **Educational only.** Do not use for production data protection.
- ⚠️ **No independent production attestation.** Repository evidence review and upstream competition analysis are not a formal security audit of this deployed composition.
- ⚠️ **Not production-ready.** No HSM integration, no key rotation, no access logging.

### References

| Standard | Relevance |
|----------|-----------|
| NIST SP 800-38D | AES-GCM specification |
| [NIST SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final) | PBKDF2 storage guidance (the historical document recommends at least 1,000 and tuning as high as practical); the 600k HMAC-SHA-256 setting follows the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), checked 2026-10-23 |
| NIST FIPS 203 (ML-KEM) | Published post-quantum KEM standard; SMAUG-T is a final KpqC competition algorithm proposed for Korean-standard development, not a published equivalent standard |
| NIST FIPS 204 (ML-DSA) | Published post-quantum signature standard; HAETAE is a final KpqC competition algorithm still under Korean standardization review, not a published equivalent standard |
| Shamir, "How to Share a Secret" (1979) | Original SSS paper |
| KpqC Competition | Korean post-quantum competition and standardization effort that selected SMAUG-T + HAETAE; selection and publication as a Korean Standard are different milestones |

---

## 🧪 Self-Evaluation

| Criterion | Score |
|-----------|-------|
| Clarity | 9/10 — Plain English first, math layered in |
| Decision usefulness | 9/10 — Fast rules table + per-algorithm "why this, not that" |
| Real-world relevance | 9/10 — Every algorithm tied to TLS, key management, real threats |
| Cognitive load | 8/10 — Structured progression, but advanced section could be deeper |
| Credibility | 9/10 — Threat model, disclaimers, and NIST/RFC references included |

**Weakness:** The browser's verification key travels inside the replaceable
container, so the demo shows consistency under that key rather than an
independently authenticated sender identity. The conditional native Rust path
also requires authenticated external C sources. CI exercises primitive native
round trips and tamper rejection from pinned captures, but that is not a full
review of either upstream implementation or the higher-level CLI.

---

*"So whether you eat or drink or whatever you do,
do it all for the glory of God." — 1 Corinthians 10:31*
