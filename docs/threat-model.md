# Quantum Vault — Threat Model

**Version:** 1.1
**Status:** Educational threat model; evidence rechecked 2026-10-23

---

## 1. Overview

This document enumerates the assets Quantum Vault is intended to protect, the
threat actors it considers, the conditional security properties it claims, and
the threats that are *out of scope* for the current design.

---

## 2. Protected Assets

| Asset | Sensitivity | Description |
|-------|-------------|-------------|
| Plaintext file $F$ | Critical | The content to be encrypted |
| File key $K$ | Critical | 256-bit AES key; exists only for the duration of encrypt/decrypt |
| KEM private keys $sk_i$ | High | Each recipient's secret; compromise of $t$ enables decryption |
| Signature private key $\text{sig\_sk}$ | High | Signs the container; the browser's ephemeral, unpinned key does not authenticate an identity |
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
Under the stated security of SMAUG-T, the probability of recovering a share's
$\text{ss}_i$ from $\text{kem\_ct}_i$ and $pk_i$ is intended to be negligible.
Under perfect threshold security of Shamir SSS, fewer than $t$ shares reveal
zero bits of $K$.  
AES-256-GCM provides 256-bit (128-bit post-quantum) symmetric security.

The browser container also carries each KEM private key encrypted by a
password-derived key. A weak password creates a separate offline-guessing route
that bypasses the need to attack the KEM (§5).

**Verdict: Conditional on the algorithm/implementation assumptions and password strength.**

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
With an independently authenticated verification key, the container's HAETAE
signature detects modification without a matching signature. The browser instead
uses an unpinned embedded key; replacing it and re-signing is not prevented (§3.4).

**Verdict: Conditional against passive access; offline password guessing and a
$t$-share active attack are out of scope (see §5).**

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
HAETAE signs the browser `SealedBox` corpus: `nonce`, `ciphertext`,
`createdAt`, `sigPublicKey`, and each participant's `iterations`,
`kemCiphertext`, `publicKey`, `salt`, `shareNonce`, `skNonce`,
`wrappedSecretKey` and `wrappedShare`. Changing these fields while retaining the
old signature invalidates that signature. Decryption aborts on signature failure
*before* any KEM or AES operation. The outer `.qvault` version, algorithm object
and Alice/Bob/Carol labels are not in that corpus; import validates them against
fixed expected values before signature verification.

Including `sigPublicKey` in the corpus does **not** prevent replacing the key and
signature together. The browser verifies the key supplied by the same container,
without an independent trust anchor. An attacker can change `createdAt`, generate
their own HAETAE keypair, replace `sigPublicKey`, and sign the changed public
corpus. It verifies under that replacement key. No original signing key or
participant password is needed to re-sign; the encrypted shares and ciphertext
stay unchanged, so this operation alone does not recover the secret.

Defending against that replacement requires a verification key authenticated
outside the replaceable container (for example, an independently authenticated
pin or a validated PKI binding). No such check is implemented in the browser.
The existing unchanged-key tamper demo proves its narrower early-rejection path.

The Rust format separately binds threshold and algorithm metadata through AES-GCM
AAD. The browser's `aes.ts` does not supply AAD; Rust-format claims must not be
assumed for the browser. AES-GCM ciphertext authentication remains a separate
check from signer-key authenticity.

**Verdict: Unchanged-signature edits are rejected; active key-and-signature
replacement is not defended in the browser. Trusted-key distribution remains
out of scope (§5).**

---

### 3.5 Quantum Attacker (Harvest Now, Decrypt Later)

**Capabilities:**  
- Stores containers today; may gain access to a sufficiently capable,
  fault-tolerant quantum computer in the future
- With such a machine, can break RSA, ECC, and Diffie-Hellman

**Threat:**  
Use Shor's algorithm to break the KEM and recover $K$; use Grover's algorithm
to brute-force AES.

**Mitigation:**  
SMAUG-T and HAETAE are based on module lattice problems (MLWE, MLWR, MSIS),
for which no efficient quantum algorithm is known. The active browser artifacts
use SMAUG-T Level 1 / HAETAE Mode 2, with stated targets bounded by category 1.
The Rust crates define Level 3 / Mode 3 native FFI, but this checkout does not
contain the external C sources and `kpqc-wasm` is an error-only scaffold. CI
downloads pinned public source captures and retains primitive native round-trip
and tamper evidence, but a working higher-level CLI is not part of that gate.

**Verdict: Post-quantum design goal, conditional on the lattice assumptions,
parameters and implementation. This repository is not a security proof.**

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
- Rust rejects container algorithm identifiers that do not match the selected
  backend before invoking it. The browser accepts only its fixed algorithm
  suite during import rather than selecting a backend from file metadata.
- The Rust `dev-backend` module and convenience APIs are omitted when that
  feature is disabled; an unacknowledged release with it enabled fails at
  compile time.

**Verdict: Enforced for the implemented fixed suites, subject to the browser's
unpinned signing-key boundary in §3.4.**

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
- **Strict length/work validation**: All fixed-size fields (including wrapped
  shares and wrapped secret keys) are validated, and PBKDF2 work factors are
  bounded integers, before processing.
- **Algorithm compatibility check**: Import rejects containers with unrecognized
  algorithm identifiers (`UNSUPPORTED_ALGORITHM` error).
- **Participant identity/position validation**: Exactly three participants in
  Alice/Bob/Carol order are required; missing, renamed, reordered or additional
  entries are rejected before signature verification.
- **No silent failures**: All validation errors produce explicit error codes
  that are surfaced to users.

**Attack surface:**
- Imported containers execute the same HAETAE verification code as locally-
  created containers — no additional code paths introduced.
- Base64 decoding failures are caught and mapped to `CORRUPTED_DATA`.
- JSON parsing errors are caught and mapped to `INVALID_JSON`.

**Verdict: Invalid signatures and malformed structures are rejected; imported
self-signed containers have the same unpinned-key limitation as §3.4. Successful
import does not authenticate an original sender.**

---

## 4. Security Properties Summary

| Property | Claim / boundary | Assumption |
|----------|------------------|------------|
| Confidentiality ($< t$ shares) | Information-theoretic (perfect secrecy) | Correct Shamir SSS |
| Confidentiality (KEM layer) | Computational | MLWE / MLWR (SMAUG-T IND-CCA2) |
| Signature integrity under a fixed authenticated key | Computational | HAETAE EUF-CMA and authentic key distribution; browser key is unpinned |
| Original-sender authenticity in the browser | Not established | Embedded key can be replaced; an independent trust anchor is absent |
| Post-quantum design goal | Computational and conditional | No efficient quantum attack is known for the stated lattice assumptions; parameters and implementation remain part of the claim |
| Post-quantum symmetric | 128-bit under Grover | AES-256 security |

---

## 5. Out of Scope / Explicitly Not Defended

The following are **not** in Quantum Vault's current threat model:

| Threat | Reason |
|--------|--------|
| **Compromise of ≥ t recipients** | Shamir provides no protection if $t$ shares are obtained legitimately or through coercion |
| **Side-channel attacks** (timing, power, EM) | See §5.1 below for detailed analysis |
| **Memory forensics** | Explicit Rust and typed-array key buffers are cleared on reviewed paths, but managed-runtime copies, Web Crypto internals, allocator remnants, OS swapping and hibernation are not an erasure boundary |
| **Offline brute-force against localStorage** | Sealed containers stored in `localStorage` are accessible to anyone with physical or OS-level access to the browser profile. An attacker can exfiltrate the container and mount an offline dictionary attack against participant passwords with no rate limiting or lockout. PBKDF2 (600 000 iterations) raises the cost but does not eliminate the risk. Users should choose strong, unique passwords. |
| **Malicious encryptor** | The encryptor can embed arbitrary plaintext; Quantum Vault makes no claims about what is encrypted |
| **Signature key distribution** | The authenticity of `sig_pk` is out of scope — a TOFU or PKI layer is required |
| **Deniability / non-repudiation** | A self-signed embedded key does not establish an original sender's identity; any stronger assertion requires independently authenticated key ownership |
| **Key revocation** | There is no mechanism to revoke a recipient's key share |
| **Quantum attacks on GF(2⁸)** | Quantum algorithms provide a small speedup for Gaussian elimination over finite fields but do not threaten SSS at current parameters |

### 5.1 Timing Side-Channel Analysis

#### HAETAE Rejection-Loop Timing Evidence

The pinned HAETAE reference signing source contains a rejection loop. One
attempt:

1. Samples a masking vector $\mathbf{y}$
2. Computes commitment $\mathbf{w}$
3. Derives challenge $c$
4. Computes response $\mathbf{z}$
5. **Rejects and restarts** if $||\mathbf{z}||$ or hints exceed norm bounds

and then restarts at `goto reject` when a bound check fails. The number of
attempts is therefore a source-level variable-work signal. The retained evidence
does **not** establish the signal's practical exploitability, quantify its
distribution, attest the timing behavior of the compiled WASM artifact, or prove
that a constant-work mitigation is impossible. Those require a separate,
controlled side-channel evaluation.

#### Why This Demo Accepts It

For Quantum Vault's demo threat model, the unquantified timing risk is accepted
with these exposure-reducing design choices:

- **Ephemeral signature keys**: Each seal operation generates a fresh HAETAE
  keypair; the application overwrites its signing-key copies after one use. The
  active HAETAE WASM lacks a volatile-C zeroization export, so its wrapper's
  `HEAPU8` overwrite is best-effort rather than a proven erasure boundary.
- **Single-use signatures**: Each secret key signs exactly one message, reducing
  opportunities to collect repeated traces under the same key. This is not a
  proof that a single observation reveals nothing.
- **No intended remote signing oracle**: Signing happens locally in the demo and
  each key is discarded after one message. This architecture reduces repeated-key
  timing exposure; browser timer restrictions are not treated as a security boundary.

#### Applied Mitigations

The two active WASM artifacts have different reproducible build histories. These
controls describe retained evidence, not a constant-time attestation:

| Mitigation | Implementation |
|------------|----------------|
| **SMAUG-T build flags** | The reproducing command uses `-O1` and disables tree/SLP vectorization; those flags reduce some compiler transformations but do not prove constant-time execution |
| **HAETAE build flags** | The reproducing command uses historical `-O2` bytes without the anti-vectorization flags; changing them would change the audited artifact |
| **Pre-allocated memory** | The active SMAUG-T artifact starts at 16 MiB and HAETAE at 32 MiB, with growth allowed; pre-allocation does not eliminate allocator or host timing variation |
| **Secure zeroing** | SMAUG-T uses its C-level `volatile` zeroing export. The active shipped HAETAE WASM has no such export; its TypeScript wrapper overwrites secret allocations through `HEAPU8` before freeing them, which is best-effort and must not be described as guaranteed erasure. |
| **Source-level review** | Reviewed source contains fixed-work primitives and arithmetic selection in important paths; compiled-WASM and cross-browser timing remain unproven |

#### SMAUG-T KEM

The pinned SMAUG-T decapsulation source uses a full-length comparison and
arithmetic conditional move for implicit rejection, and does not call the RNG.
That removes obvious early-exit validity branches, but the retained evidence does
not prove the compiled module is constant-time for valid versus invalid ciphertexts.

#### Recommended Monitoring

Timing harnesses are provided for evidence collection. A low coefficient of
variation is not proof of constant-time behavior: any review must retain raw
interleaved samples, environment details, a predefined threshold and a negative
control, then investigate differences across representative browsers and CPUs.

---

## 6. Implementation Security Requirements

All implementations MUST:

1. Verify the container signature **before** any KEM decapsulation or AES
   decryption.
2. Clear the file key $K$ and intermediate shared secrets on every reachable
   exit, while documenting the limits of best-effort erasure in managed/WASM
   runtimes.
3. Use a cryptographically secure random generator for $K$, container identity
   and Shamir coefficients. The Rust outer nonce is HKDF-derived from the random
   16-byte `container_id`; the browser samples its 12-byte outer nonce directly.
4. Enforce the format-specific bounds: Rust accepts at most 8 MiB serialized and
   4 MiB ciphertext; the browser accepts at most 64 MiB decoded ciphertext plus
   exact fixed field sizes and rejects import files over 90 MiB before reading
   their text.
5. Validate structural constraints, algorithm identifiers and backend matches
   before cryptographic processing.
6. Keep `dev-backend` out of a production build; the current release guard
   rejects it unless an explicit development-only acknowledgement is supplied.
