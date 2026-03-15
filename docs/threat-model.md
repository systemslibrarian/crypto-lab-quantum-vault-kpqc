# Quantum Vault — Threat Model

**Version:** 1.0  
**Status:** Stable

---

## 1. Overview

This document enumerates the assets Quantum Vault protects, the threat actors
it considers, the security properties it guarantees, and the threats that are
*out of scope* for the current design.

---

## 2. Protected Assets

| Asset | Sensitivity | Description |
|-------|-------------|-------------|
| Plaintext file $F$ | Critical | The content to be encrypted |
| File key $K$ | Critical | 256-bit AES key; exists only for the duration of encrypt/decrypt |
| KEM private keys $sk_i$ | High | Each recipient's secret; compromise of $t$ enables decryption |
| Signature private key $\text{sig\_sk}$ | High | Used to authenticate the container |
| KEM public keys $pk_i$ | Low | Public but integrity-critical (substitution enables MITM) |
| Signature public key $\text{sig\_pk}$ | Low | Needed for verification; must be distributed authentically |
| Container ciphertext | Medium | Exposure reveals algorithm choices and share count but not $F$ |

---

## 3. Threat Actors

### 3.1 Passive Network Attacker (Classical)

**Capabilities:**  
- Observes all transmitted data (containers, public keys)
- Cannot modify data in transit

**Threat:**  
Recovers $F$ from the container without possessing private keys.

**Mitigation:**  
Under IND-CPA security of SMAUG-T, the probability of recovering a share's
$\text{ss}_i$ from $\text{kem\_ct}_i$ and $pk_i$ is negligible.  
Under perfect threshold security of Shamir SSS, fewer than $t$ shares reveal
zero bits of $K$.  
AES-256-GCM provides 256-bit (128-bit post-quantum) symmetric security.

**Verdict: Defended.**

---

### 3.2 Insider / Colluding Participants (Classical)

**Capabilities:**  
- Controls up to $t-1$ recipients (holds their private keys)
- Can share their partial decryptions

**Threat:**  
Reconstruct $K$ and decrypt $F$ with fewer than $t$ shares.

**Mitigation:**  
Any $t-1$ or fewer shares are information-theoretically independent of $K$.
The colluding participants learn *nothing* about $K$ beyond what they already
know.

**Verdict: Defended (unconditionally — assumes correct Shamir SSS).**

---

### 3.3 Storage / Backup Compromise (Classical)

**Capabilities:**  
- Read access to the container file on disk or in storage
- May have access to up to $t-1$ KEM private keys

**Threat:**  
Recover $F$ from a stolen backup.

**Mitigation:**  
As above — fewer than $t$ shares provide no information about $K$.
The container's HAETAE signature prevents silent modification before a
compromised $t$-share attack.

**Verdict: Defended against passive access; $t$-share active attack is out of scope (see §5).**

---

### 3.4 Active Container Tampering

**Capabilities:**  
- Can modify the container in transit or at rest
- Does not hold any private keys

**Threat:**  
- Replace the KEM ciphertext for one share with one for a different recipient,
  redirecting a partial decryption.
- Truncate or corrupt the ciphertext.
- Modify the `threshold` field to weaken the policy.

**Mitigation:**  
HAETAE signs the following container fields: `nonce`, `ciphertext`, all per-participant
`kemCiphertext`, `wrappedShare`, `shareNonce`, `publicKey`, `wrappedSecretKey`, and `skNonce`
values, plus the signature verification key `sigPublicKey` and the `createdAt` timestamp.
Any modification to these fields invalidates the signature.
Decryption aborts on signature failure *before* any KEM or AES operation.

The binding of `sigPublicKey` in the signed corpus prevents an attacker from substituting
the signature and verification key pair while preserving container integrity.

The AAD in AES-256-GCM additionally binds the threshold and algorithm choice to
the ciphertext, providing a second layer of defense.

**Verdict: Defended.**

---

### 3.5 Quantum Attacker (Harvest Now, Decrypt Later)

**Capabilities:**  
- Stores containers today; executes large quantum computers in the future
- Can break RSA, ECC, and Diffie-Hellman

**Threat:**  
Use Shor's algorithm to break the KEM and recover $K$; use Grover's algorithm
to brute-force AES.

**Mitigation:**  
SMAUG-T and HAETAE are based on module lattice problems (MLWE, MLWR, MSIS),
believed to resist known quantum algorithms at Level 3 (≈128 bits
post-quantum security). AES-256 provides ≥128 bits even under Grover's
algorithm.

**Verdict: Defended (assuming lattice assumptions hold against quantum adversaries).**

---

### 3.6 Algorithm-Substitution / Downgrade

**Capabilities:**  
- Can intercept and modify the container's `kem_algorithm` or `sig_algorithm`
  field before a recipient processes it.

**Threat:**  
Convince a recipient to use the weak `dev-backend` or a future weaker
algorithm.

**Mitigation:**  
- The `kem_algorithm` and `sig_algorithm` fields are covered by the HAETAE
  signature; modification is detectable.
- The AAD includes both algorithm IDs and the container version; a downgraded
  algorithm produces a different AAD, causing AES-GCM decryption to fail.
- The `dev-backend` compile-error guard prevents it from shipping in release
  builds (`cfg!(not(debug_assertions))`).

**Verdict: Defended.**

---

### 3.7 Malicious `.qvault` File Import

**Capabilities:**  
- Can craft or modify a `.qvault` export file and trick a user into importing it.
- May attempt to inject containers with:
  - Invalid HAETAE signatures
  - Modified ciphertext or share data
  - Incorrect byte lengths to trigger parser bugs

**Threat:**  
- Convince a user to decrypt a tampered container (integrity violation)
- Exploit parser bugs to cause denial of service or memory corruption
- Cross-container attacks: splice shares from different containers

**Mitigation:**  
- **Signature-first verification**: The import path verifies the HAETAE
  signature before any KEM or AES operation. Invalid signatures abort
  import with `SIGNATURE_INVALID` error before data enters the vault.
- **Strict length validation**: All fixed-size fields (nonce, KEM ciphertext,
  public keys) are validated against expected byte lengths before processing.
- **Algorithm compatibility check**: Import rejects containers with unrecognized
  algorithm identifiers (`UNSUPPORTED_ALGORITHM` error).
- **Participant count validation**: Exactly 3 participants required; other
  counts are rejected before signature verification.
- **No silent failures**: All validation errors produce explicit error codes
  that are surfaced to users.

**Attack surface:**
- Imported containers execute the same HAETAE verification code as locally-
  created containers — no additional code paths introduced.
- Base64 decoding failures are caught and mapped to `CORRUPTED_DATA`.
- JSON parsing errors are caught and mapped to `INVALID_JSON`.

**Verdict: Defended against integrity attacks; import uses existing verified code paths.**

---

## 4. Security Properties Summary

| Property | Guarantee | Assumption |
|----------|-----------|------------|
| Confidentiality ($< t$ shares) | Information-theoretic (perfect secrecy) | Correct Shamir SSS |
| Confidentiality (KEM layer) | Computational | MLWE / MLWR (SMAUG-T IND-CCA2) |
| Integrity | Computational | MSIS (HAETAE EUF-CMA) |
| Authenticity | Computational | HAETAE EUF-CMA |
| Quantum resistance | Computational | Lattice hard problems resist quantum |
| Post-quantum symmetric | 128-bit under Grover | AES-256 security |

---

## 5. Out of Scope / Explicitly Not Defended

The following are **not** in Quantum Vault's current threat model:

| Threat | Reason |
|--------|--------|
| **Compromise of ≥ t recipients** | Shamir provides no protection if $t$ shares are obtained legitimately or through coercion |
| **Side-channel attacks** (timing, power, EM) | See §5.1 below for detailed analysis |
| **Memory forensics** | Key material is zeroized but OS page swapping or hibernation may persist it before zeroization |
| **Offline brute-force against localStorage** | Sealed containers stored in `localStorage` are accessible to anyone with physical or OS-level access to the browser profile. An attacker can exfiltrate the container and mount an offline dictionary attack against participant passwords with no rate limiting or lockout. PBKDF2 (600 000 iterations) raises the cost but does not eliminate the risk. Users should choose strong, unique passwords. |
| **Malicious encryptor** | The encryptor can embed arbitrary plaintext; Quantum Vault makes no claims about what is encrypted |
| **Signature key distribution** | The authenticity of `sig_pk` is out of scope — a TOFU or PKI layer is required |
| **Deniability** | The HAETAE signature creates a non-repudiable binding between the signer and the container |
| **Key revocation** | There is no mechanism to revoke a recipient's key share |
| **Quantum attacks on GF(2⁸)** | Quantum algorithms provide a small speedup for Gaussian elimination over finite fields but do not threaten SSS at current parameters |

### 5.1 Timing Side-Channel Analysis

#### Inherent HAETAE Timing Leak

HAETAE (and all Fiat-Shamir with Aborts lattice signatures — including Dilithium/ML-DSA)
have an **inherent variable-time signing operation**. The core signing loop:

1. Samples a masking vector $\mathbf{y}$
2. Computes commitment $\mathbf{w}$
3. Derives challenge $c$
4. Computes response $\mathbf{z}$
5. **Rejects and restarts** if $||\mathbf{z}||$ or hints exceed norm bounds

The rejection loop (`goto reject;`) cannot be made constant-time without fundamentally
changing the algorithm. Iteration count follows a geometric distribution (≈2.5 iterations
average for HAETAE Mode 2).

#### Why This Is Acceptable

For Quantum Vault's threat model, this timing leak is acceptable because:

- **Ephemeral signature keys**: Each seal() operation generates a fresh HAETAE keypair;
  the signing key is immediately zeroized and never reused.
- **Single-use signatures**: Each secret key signs exactly one message, eliminating
  the timing oracle attack vector that requires observing many signatures under
  the same key.
- **No remote timing**: The browser context provides limited timing precision (~5 µs
  with isolation headers); cross-origin attackers cannot measure seal() duration.

#### Applied Mitigations

The WASM build applies the following timing hardening measures:

| Mitigation | Implementation |
|------------|----------------|
| **Reduced optimization** | `-O1` instead of `-O2` to minimize timing-variant instruction scheduling |
| **Anti-vectorization** | `-fno-tree-vectorize -fno-slp-vectorize` to prevent data-dependent SIMD |
| **Pre-allocated memory** | `-s INITIAL_MEMORY=4194304` (4 MiB) to eliminate `_malloc` timing jitter |
| **Secure zeroing** | C-level `volatile` zeroing via `_*_secure_zeroize()` exports, immune to JS engine elision |
| **Constant-time primitives** | SHAKE256 (deterministic expansion), shift-and-mask norm bounds (no branches per coefficient) |

#### SMAUG-T KEM

SMAUG-T encapsulation and decapsulation are deterministic fixed-iteration algorithms.
No rejection sampling occurs, so timing is effectively constant for a given ciphertext size.

#### Recommended Monitoring

A timing harness is provided at `timing-harness.html` for empirical validation.
Distributions with low coefficient of variation (< 5%) indicate acceptable
constant-time behavior. Higher variance should be investigated.

---

## 6. Implementation Security Requirements

All implementations MUST:

1. Verify the container signature **before** any decryption operation.
2. Zeroize the file key $K$ and all intermediate shared secrets from memory.
3. Use a cryptographically secure random number generator for $K$, $\text{nonce}$, and SSS polynomial coefficients.
4. Reject containers exceeding 64 MiB to prevent memory exhaustion.
5. Validate all structural constraints (threshold ≥ 2, nonce length = 12, shares count matches `share_count`) before processing.
6. Never enable `dev-backend` in production builds.
