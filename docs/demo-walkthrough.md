# Quantum Vault — Demo Walkthrough

**Version:** 1.0  
**Date:** 2026-10-23
**Applies to:** Web demo v5.1 (real KpqC WASM)

---

## Overview

The web demo is a single-page application that presents a 3×3 grid of nine
numbered safety deposit boxes (01–09). In English, three of them (03, 06, 09)
are pre-sealed on first use with SMAUG-T Level 1 KEM and HAETAE Mode 2
signatures from the KpqC competition reference implementations. The remaining
six boxes are empty and can be filled with your own secrets.

The SMAUG-T and HAETAE operations run inside Emscripten-compiled WebAssembly.
AES-GCM and PBKDF2 use the browser's Web Crypto API, and Shamir splitting and
reconstruction use the TypeScript implementation in this repository. The
active browser pipeline has no mock KEM/signature substitutions or pre-computed
cryptographic results.

---

## 1. The Vault Wall

On first use the application calls `generateDemoBoxes()`, which runs three full
`sealMessage()` pipelines (one per demo box) before rendering the wall. Fresh
random keys, salts and nonces make each newly generated container different,
while the documented passwords still unlock it. The generated boxes persist in
`localStorage`; an ordinary reload reuses that stored state rather than sealing
the demos again.

Box appearance:

| Class | Meaning |
|-------|---------|
| `empty` | No secret stored |
| `occupied` | A sealed secret is present |
| `selected` | The box is currently active in the side panel |

Clicking a box (or pressing Enter / Space on it) opens the side panel.  An
occupied box shows the **Retrieve** form; an empty box shows the **Deposit**
form.

---

## 2. Pre-Loaded Demo Boxes

These three boxes are generated on first use and by the explicit **Reset vault**
action. Switching language replaces tracked demo boxes with that language's demo
set. **Clear vault** deliberately persists an empty vault, so an ordinary reload
does not restore cleared boxes.

| Box | Secret | Alice's key | Bob's key | Carol's key |
|-----|--------|-------------|-----------|-------------|
| 03 | `The treasure map is under the old oak tree` | `ruby` | `emerald` | `diamond` |
| 06 | `Launch code: ALPHA-7749-ZULU` | `fortress` | `bastion` | `citadel` |
| 09 | `The meeting is moved to Friday at noon` | `monday` | `tuesday` | `wednesday` |

Any two of the three listed passwords unlock each box.  Entering only one is
not enough, even with the correct password — this demonstrates the 2-of-3
threshold property.

---

## 3. Deposit Flow (Sealing a New Secret)

Click an **empty** box to open the Deposit panel.

### 3.1 Input Validation and Options

| Field | Rule |
|-------|------|
| Secret message | Must not be empty |
| Alice / Bob / Carol key | Minimum 4 characters; all three must be distinct |

A **"Show passwords"** checkbox is available to reveal typed passwords.

Validation is client-side only; it runs before any cryptographic work starts.

### 3.2 Pipeline Animation

When "Seal deposit box" is pressed, four steps light up sequentially — each
representing a real cryptographic operation:

```
AES-256-GCM  →  Shamir split  →  SMAUG-T wrap  →  HAETAE sign
```

**What each step actually does:**

**AES-256-GCM**  
`crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 })` generates a 256-
bit file key K.  The UTF-8–encoded message is encrypted to produce a ciphertext
C and a 96-bit random nonce IV.

**Shamir split**  
The 32 raw bytes of K are split into 3 shares over GF(2⁸) with polynomial
`0x11d`, threshold t = 2.  Each share is an (index, 32-byte data) pair.
Reconstructing any 2 of the 3 shares recovers K exactly; 1 share reveals
nothing.

**SMAUG-T wrap** (runs three times in parallel, one per keyholder)  
For each participant:
1. `smaug_keypair()` (WASM) generates a fresh 672-byte public key and 832-byte
   secret key.
2. `smaug_encapsulate()` encapsulates a 32-byte shared secret SS using the
   public key, producing a 672-byte KEM ciphertext.
3. The 32-byte share is AES-256-GCM encrypted using SS as the key.
4. The SMAUG-T secret key itself is encrypted with a key derived by
   PBKDF2-SHA-256 (600 000 iterations) from the participant's password.

Only the KEM ciphertext and shared secret in that sequence are SMAUG-T outputs.
The password salt and AES-GCM nonces come from browser randomness, while Web
Crypto produces the encrypted share and encrypted secret key. The persisted
salt, KEM ciphertext, wrapped share, wrapped secret key and nonces form a
`WrappedShare` record; the shared secret itself is not stored.

**HAETAE sign**  
A one-time HAETAE Mode 2 keypair (992-byte VK, 1408-byte SK) is generated. The
signed message is compact UTF-8 JSON with alphabetically ordered keys and
base64-encoded byte arrays. It contains these persistent `SealedBox` fields:

```
ciphertext, createdAt, nonce, sigPublicKey,
wrappedShares[iterations, kemCiphertext, publicKey, salt,
              shareNonce, skNonce, wrappedSecretKey, wrappedShare]
```

`haetae_sign()` produces a signature of up to 1474 bytes.  The verification
key VK is stored in `sigPublicKey` alongside the container.  The signing key SK
is discarded. Because the verification key travels inside the same container
and is not pinned to an external identity, this demonstrates consistency under
the included key, not original-sender authentication against wholesale
key-and-signature replacement.

### 3.3 Result

The box turns to `occupied` state.  "Secret sealed in box XX. ✓" appears in the
panel.

---

## 4. Retrieve Flow (Opening a Sealed Box)

Click an **occupied** box to open the Retrieve panel.

### 4.1 Password Entry

Enter any combination of Alice, Bob, and Carol passwords.  Leave a field blank
to skip that participant.  Input fields are `type="password"` (masked).

At least two correct passwords are required; the entry form does not enforce a
minimum, so the threshold failure path can be explored deliberately.

### 4.2 Pipeline Animation

```
HAETAE verify  →  SMAUG-T unlock  →  Shamir reconstruct  →  AES-256-GCM
```

**What each step actually does:**

**HAETAE verify**  
Before any decryption is attempted, `haetae_verify()` (WASM) checks the
container signature over the same canonical JSON used at seal time. A
return value of zero means the container is intact; non-zero stops the pipeline
immediately and returns a failure result without touching the ciphertext.

This step catches bit-flips, truncation, reordering of shares, or other changes
to the signed fields under the selected embedded key. It does not establish who
created the container, because an attacker who can replace the whole container
can also supply a new key and signature.

**SMAUG-T unlock** (per non-empty password)  
For each field that was filled in:
1. PBKDF2-SHA-256 (600 000 iterations) over the participant's password and the
   stored 16-byte salt re-derives the AES key.
2. AES-256-GCM decrypts the wrapped SMAUG-T SK.  A wrong password causes an
   AES-GCM auth-tag mismatch → `DOMException`; the share is silently skipped.
3. `smaug_decapsulate()` (WASM) uses the recovered SK to derive the same SS from
   the stored KEM ciphertext.
4. AES-256-GCM decrypts the wrapped share using SS.

**Shamir reconstruct**  
`reconstructSecret()` runs Lagrange interpolation over GF(2⁸) with however many
valid shares were recovered. With one share it returns an underdetermined
candidate rather than throwing; that candidate is authenticated in the next
step.

With one valid share, the core still passes the Lagrange output to AES-GCM so
the authentication tag provides the actual acceptance decision. The UI then
marks `Shamir reconstruct` as a warning and does not animate the AES step. With
zero valid shares, reconstruction and AES-GCM are skipped.

**AES-256-GCM**  
`crypto.subtle.decrypt` attempts to decrypt the ciphertext with the reconstructed
key. With exactly one valid share, the reconstruction is independent of the
unknown secret from the attacker's view and normally fails the 16-byte GCM
authentication tag. With two or three valid shares, decryption succeeds. The
tag—not the share count—is the core's final acceptance test.

### 4.3 Success Path

The revealed message appears letter-by-letter with a brief scramble animation
before each character settles.  Spaces appear instantly.  The character source
is genuine decryption output, not pre-stored plaintext.

### 4.4 Failure Paths

In **every** failure path the cycling gibberish shown before ACCESS DENIED is
freshly generated by `crypto.getRandomValues` in `pipeline.ts` — it is never
derived from key or share material. The display input is bounded to 8–256 bytes,
regardless of ciphertext size. `showGibberish` in `ui/reveal.ts` then XORs
those random bytes against `cycle * 37 + i` on each of its four ~120 ms frames
purely to make the strip flicker. The *key strip* is the part that shows real
bytes: it renders the genuine Lagrange candidate, whether authenticated or not.

**Wrong password(s) — threshold not met:**  
With one recovered share, the core reconstructs a candidate and attempts
AES-GCM authentication; the UI animation reaches `Shamir reconstruct`, marks it
`warn` and does not animate the already-completed AES attempt. The key strip
shows that genuine candidate; the ~480 ms gibberish strip before ACCESS DENIED
is random bytes. With no recovered share, there is no Lagrange output to show.

**HAETAE verify fails (tampered container):**  
The pipeline halts before SMAUG-T unlock.  No share is unwrapped and no
decryption of any sort is performed, so there is no Lagrange output to show —
only the random-byte gibberish strip.

**One valid share:**
SMAUG-T unlock succeeds for one share; Shamir reconstruction produces a
candidate key; AES-GCM normally rejects it on the authentication tag. This is
the one-share case described above: the key strip shows the real reconstruction
candidate, and the gibberish strip is again random bytes.

---

## 5. What Is Real vs. What Is Visualisation

| Element | Real cryptography? |
|---------|-------------------|
| SMAUG-T keypair / encapsulate / decapsulate | Yes — WASM from KpqC reference C |
| HAETAE keypair / sign / verify | Yes — WASM from KpqC reference C |
| AES-256-GCM encrypt / decrypt | Yes — `window.crypto.subtle` |
| PBKDF2-SHA-256 key derivation | Yes — `window.crypto.subtle` |
| Shamir GF(2⁸) split / reconstruct | Yes — TypeScript implementation |
| Pipeline step animation timing | Visual only (500 ms `sleep()` per step) |
| Letter-by-letter reveal | Visual only (the decrypted string is known before animation starts) |
| Gibberish animation cycles | Visual only — fresh `crypto.getRandomValues` bytes, displayed with cycling XOR masks |
| Key strip after a failed open | Yes — the genuine, unauthenticated Lagrange candidate |

---

## 6. Parameter Summary

| Parameter | Value |
|-----------|-------|
| Shares (n) | 3 |
| Threshold (t) | 2 |
| AES key size | 256 bits |
| GCM nonce | 96 bits (random per seal) |
| PBKDF2 iterations | 600 000 |
| PBKDF2 salt | 16 bytes (random per participant per seal) |
| SMAUG-T level | Level 1 — lowest SMAUG-T parameter set, NIST PQC category 1 (≈ AES-128) |
| HAETAE mode | Mode 2 — lowest HAETAE parameter set, NIST PQC category 2 |
| GF(2⁸) polynomial | 0x11d (generator 2 has order 255) |
