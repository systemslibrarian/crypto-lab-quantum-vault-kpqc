# Quantum Vault — v5.0

**A threshold secret-storage demo running real post-quantum cryptography in the browser.**

Quantum Vault encrypts short secrets with **AES-256-GCM**, splits the key using **Shamir Secret Sharing (GF(2⁸))**, wraps each share with **SMAUG-T Level 1 KEM** (key encapsulation), and seals the container with a **HAETAE Mode 2 signature**.

Every cryptographic primitive executes inside the browser as WebAssembly — compiled from the official C reference implementations of the KpqC competition finalists. **There are no mocks, no HMAC substitutes, no polyfills.**

---

## Live Demo

👉 **[systemslibrarian.github.io/quantum-vault-kpqc](https://systemslibrarian.github.io/quantum-vault-kpqc/)**

Three demo boxes are pre-sealed on first visit. Each requires two correct passwords (2-of-3 threshold).

| Box | Secret | Alice | Bob | Carol |
|-----|--------|-------|-----|-------|
| 03 | *The treasure map is under the old oak tree* | `ruby` | `emerald` | `diamond` |
| 08 | *Launch code: ALPHA-7749-ZULU* | `fortress` | `bastion` | `citadel` |
| 10 | *The meeting is moved to Friday at noon* | `monday` | `tuesday` | `wednesday` |

Unlock any box by entering **any two** of its three passwords.

---

## Cryptographic Stack

| Layer | Algorithm | Notes |
|-------|-----------|-------|
| Symmetric encryption | **AES-256-GCM** | Web Crypto API |
| Key splitting | **Shamir Secret Sharing** | GF(2⁸), evaluation polynomial over 256-byte shares |
| Post-quantum KEM | **SMAUG-T Level 1** | KpqC standard — PK 672 B, SK 832 B, CT 672 B, SS 32 B |
| Post-quantum signature | **HAETAE Mode 2** | KpqC standard — PK 992 B, SK 1408 B, max-sig 1474 B |

### Why KpqC rather than NIST PQC?

The NIST PQC process selected ML-KEM (Kyber) and ML-DSA (Dilithium). This project deliberately chooses the KpqC finalists (SMAUG-T + HAETAE) as an exercise in exploring alternative algorithm families — lattice-based designs with different parameter choices and design tradeoffs. A hybrid mode combining both families is a future goal.

---

## Seal / Open Pipeline

### Sealing a secret (deposit)

```
1. AES-256-GCM
   random 256-bit key → encrypt plaintext → (ciphertext, nonce)

2. Shamir split
   32-byte AES key → 3 shares, threshold = 2  (GF(2⁸) polynomial)

3. SMAUG-T wrap  (repeated 3× — once per participant)
   a. SMAUG-T keygen()         → (publicKey PK, secretKey SK)
   b. SMAUG-T encapsulate(PK)  → (kemCiphertext, sharedSecret)
   c. AES-GCM(sharedSecret)    → wrappedShare
   d. PBKDF2(password, salt)   → passwordKey
   e. AES-GCM(passwordKey, SK) → wrappedSecretKey

4. HAETAE sign
   haetaeKeypair()                  → (sigPK, sigSK)
   haetaeSign(containerBytes, sigSK) → signature
   store sigPK alongside the container
```

### Opening a secret (retrieve)

```
1. HAETAE verify
   haetaeVerify(signature, containerBytes, sigPK) → reject if invalid

2. SMAUG-T unlock  (for each submitted password)
   PBKDF2(password, salt) → passwordKey
   AES-GCM decrypt wrappedSecretKey → SK      (throws if wrong password)
   smaugDecapsulate(kemCiphertext, SK) → sharedSecret
   AES-GCM(sharedSecret) decrypt wrappedShare → Shamir share

3. Shamir reconstruct
   ≥ 2 shares → AES key   (wrong if < 2 shares)

4. AES-256-GCM decrypt
   AES-GCM(reconstructedKey) → plaintext      (throws if key wrong)
```

---

## Project Layout

```
quantum-vault-kpqc/
│
├─ crates/
│   ├─ qv-core/       ← Rust crypto library (AES-GCM + Shamir + 45 unit tests)
│   └─ qv-cli/        ← CLI binary
│
├─ wasm/
│   ├─ build.sh                ← Emscripten build script (read-only; run locally)
│   ├─ src/
│   │   ├─ randombytes_wasm.c  ← routes to crypto.getRandomValues
│   │   ├─ smaug_exports.c     ← SMAUG-T exported entry points
│   │   └─ haetae_exports.c    ← HAETAE exported entry points
│   ├─ dist/                   ← (gitignored) compiled JS+WASM
│   └─ vendor/                 ← (gitignored) C reference implementations
│
├─ web-demo/
│   ├─ index.html
│   ├─ src/
│   │   ├─ main.ts             ← entry point; calls initCrypto() before vault init
│   │   ├─ crypto/
│   │   │   ├─ init.ts         ← parallel WASM module initialization
│   │   │   ├─ smaug.ts        ← SMAUG-T WASM wrapper
│   │   │   ├─ haetae.ts       ← HAETAE WASM wrapper
│   │   │   ├─ keywrap.ts      ← SMAUG-T KEM + PBKDF2 share wrapping
│   │   │   ├─ pipeline.ts     ← seal/open orchestration
│   │   │   ├─ aes.ts          ← AES-256-GCM helpers
│   │   │   ├─ shamir.ts       ← Shamir SSS over GF(2⁸)
│   │   │   └─ wasm/           ← Emscripten JS loaders (committed)
│   │   ├─ vault/
│   │   │   ├─ demo.ts         ← generates the three pre-sealed demo boxes
│   │   │   └─ state.ts        ← localStorage persistence / serialization
│   │   └─ ui/
│   │       ├─ wall.ts         ← vault-wall rendering
│   │       ├─ panel.ts        ← deposit / retrieve panel
│   │       ├─ pipeline-ui.ts  ← animated pipeline steps
│   │       ├─ reveal.ts       ← message reveal / gibberish animation
│   │       └─ styles/vault.css
│   └─ public/
│       ├─ smaug.wasm          ← compiled SMAUG-T Level 1 binary (committed)
│       └─ haetae.wasm         ← compiled HAETAE Mode 2 binary (committed)
│
├─ docs/
│   ├─ architecture.md
│   ├─ container-format.md
│   ├─ demo-build-notes.md
│   ├─ kat-test-vectors.md
│   └─ security-analysis.md
│
├─ .github/workflows/deploy-pages.yml
└─ README.md
```

---

## Running the Web Demo Locally

```bash
cd web-demo
npm install
npm run dev          # Vite dev server → http://localhost:5173
```

**Build for production:**

```bash
npm run build        # outputs to web-demo/dist/
```

The Vite config sets `base: '/quantum-vault-kpqc/'` to match the GitHub Pages subdirectory.

---

## Rebuilding the WASM Modules

The compiled `.wasm` + Emscripten loader `.js` files are committed to the repo so the web demo deploys without a C toolchain. To rebuild from source:

```bash
# 1. Install and activate Emscripten (one-time)
git clone https://github.com/emscripten-core/emsdk ~/emsdk
cd ~/emsdk && ./emsdk install 5.0.3 && ./emsdk activate 5.0.3
source ~/emsdk/emsdk_env.sh

# 2. Restore vendor sources (gitignored)
#    SMAUG-T:
git clone https://github.com/hmchoe0528/SMAUG-T_public \
  wasm/vendor/smaug-t
#    HAETAE — download HAETAE-1.1.2.zip from the KpqC submission page and:
unzip HAETAE-1.1.2.zip -d wasm/vendor/haetae

# 3. Build
bash wasm/build.sh

# 4. Copy outputs
cp wasm/dist/smaug.js  web-demo/src/crypto/wasm/smaug.js
cp wasm/dist/haetae.js web-demo/src/crypto/wasm/haetae.js
cp wasm/dist/smaug.wasm  web-demo/public/smaug.wasm
cp wasm/dist/haetae.wasm web-demo/public/haetae.wasm
```

### Verified WASM sizes (Emscripten 5.0.3, -O2)

| Module | PK | SK | CT/maxSig | SS |
|--------|----|----|-----------|-----|
| SMAUG-T Level 1 | 672 B | 832 B | 672 B | 32 B |
| HAETAE Mode 2 | 992 B | 1408 B | 1474 B (max) | — |

Round-trip tests confirmed:
- SMAUG-T: encapsulate → decapsulate → shared secrets match ✓
- HAETAE: sign → verify → returns 0 (valid) ✓

---

## Rust CLI

The `qv-core` crate provides the same cryptographic stack in Rust (AES-256-GCM + Shamir SSS, with a pluggable backend interface designed for KpqC FFI).

```bash
cargo build --release
cargo test           # 45 unit tests
cargo bench          # criterion benchmarks
```

---

## Security Notes

- All secrets and keys stay in the browser — nothing is transmitted to a server.
- PBKDF2 with 100,000 SHA-256 iterations is used to derive a password-wrapping key for the SMAUG-T secret key. This means brute-forcing a weak password is possible; use strong passwords for real secrets.
- SMAUG-T does not support deterministic keygen from a seed, so a fresh random keypair is generated per deposit. The secret key is encrypted with the password-derived key; the ciphertext and public key are stored in the container.
- The HAETAE signing keypair is ephemeral (generated at seal time) and the public key is stored in the container. This provides authentication but not attribution — anyone who reads the public key can verify the seal but cannot determine who created it.
- The WASM binaries are the official KpqC reference implementations, not production-hardened code. They have not been audited for side-channel resistance.

---

## License

MIT — see [LICENSE](LICENSE).

Quantum Vault is an experimental cryptography project exploring how **threshold cryptography** and **post-quantum cryptography** can be combined to protect encrypted files.

The system encrypts files with **AES-256-GCM**, splits the encryption key using **Shamir Secret Sharing**, and protects those shares using **post-quantum cryptographic primitives**.

---

## Interactive Cryptography Demo

Quantum Vault includes an interactive web demo that visualizes threshold cryptography using a deck of playing cards.

Instead of encrypting a file, the demo encrypts the ordering of a shuffled deck. Each cryptographic step becomes visible:

- Encryption flips the cards face-down (AES-256-GCM)
- The key splits into share cards dealt to participants (Shamir Secret Sharing)
- Each share is locked with post-quantum encryption (SMAUG-T)
- A cryptographic seal stamps across the container (HAETAE)

The user selects which participants contribute their shares. If the threshold is met, the cards flip face-up and the original order is restored. If not, the cards stay dark.

### Demo Preview

![Quantum Vault Demo](docs/demo-preview.png)

---

## Design Goals

Quantum Vault explores a security model where **no single person can decrypt a file alone**.

A threshold number of authorized participants must cooperate to reconstruct the encryption key.

Example:
```
Shares: 5  Threshold: 3
```

Any **3 of the 5 participants** can recover the key and decrypt the file.

---

## Cryptographic Stack

Quantum Vault uses the following algorithms:

| Layer | Algorithm | Purpose |
|------|-----------|---------|
| Symmetric Encryption | AES-256-GCM | Encrypt file contents |
| Secret Sharing | Shamir Secret Sharing | Split encryption key into shares |
| Post-Quantum KEM | SMAUG-T | Protect each share with PQ encryption |
| Post-Quantum Signature | HAETAE | Sign and verify encrypted containers |

This architecture allows the system to remain secure even in a **future with quantum computers**.

### A Note on Algorithm Choice

SMAUG-T and HAETAE are candidates from the **KpqC (Korean Post-Quantum Cryptography)** competition — not the NIST PQC standardization process, which selected ML-KEM (Kyber) and ML-DSA (Dilithium).

This is a deliberate choice. The KpqC candidates represent active research with different design tradeoffs, and part of the purpose of Quantum Vault is to explore algorithms outside the NIST selections.

That said, NIST-standardized algorithms carry more ecosystem support, more reference implementations, and broader third-party scrutiny. A planned **hybrid mode** will allow combining KpqC and NIST algorithms together, giving users the option to layer both.

---

## High-Level Encryption Flow

```
File
  ↓
AES-256-GCM encryption
  ↓
Random 256-bit file key
  ↓
Shamir Secret Sharing
  ↓
Multiple key shares created
  ↓
Each share protected using SMAUG-T
  ↓
Container signed with HAETAE
  ↓
.qvault encrypted file
```

## Decryption Flow

```
Load container
  ↓
Verify HAETAE signature
  ↓
Decrypt shares using SMAUG-T
  ↓
Reconstruct AES key using Shamir Secret Sharing
  ↓
Decrypt file with AES-256-GCM
```

---

## Web Demo — Encrypt a Deck of Cards

A deck of cards is small, visual, and universally understood — making it an ideal way to demonstrate threshold encryption. Every layer of the cryptographic stack maps to something the user can see.

### What Gets Encrypted

The demo encrypts the **permutation** of a shuffled deck — not the card names or images. A shuffled deck is represented as an array of integers:

```
[12, 3, 44, 9, 27, 51, ...]
```

This keeps the encrypted payload extremely small, the demo fast, and the cryptography real.

### Encryption

1. 52 cards appear face-up on screen — the user can shuffle them
2. The user hits **Encrypt** — the cards flip face-down (AES-256-GCM)
3. The encryption key shatters into share cards dealt to participants (Shamir Secret Sharing)
4. Each share card is locked with a PQ padlock icon (SMAUG-T encapsulation)
5. A cryptographic seal stamps across the container (HAETAE signature)

### Decryption

1. Participants sit at a virtual table — the user selects which ones contribute
2. HAETAE verifies the container seal
3. SMAUG-T unlocks each selected share
4. Shamir reconstructs the AES key (only if the threshold is met)
5. The cards flip face-up — the user can verify the original order is intact

### Threshold Failure

If fewer shares than the threshold are selected, reconstruction fails and the cards stay face-down. This makes the threshold concept immediately tangible.

### Visual Mapping

| Cryptographic Layer | Visual Representation |
|------|-----------|
| AES-256-GCM encryption | Cards flip face-down |
| Shamir Secret Sharing | Key splits into share cards dealt to participants |
| SMAUG-T encapsulation | Lock icon on each share card |
| HAETAE signature | Seal stamped across the container |
| Threshold failure | Cards stay dark when too few shares are contributed |

---

## Web Demo Architecture

The browser demo runs the cryptographic pipeline client-side using **WebAssembly**. No files or keys ever leave the browser.

### Phased Implementation

The demo runs the real cryptographic pipeline in the browser.

The initial version uses real AES-256-GCM encryption and real Shamir Secret Sharing compiled from Rust to WebAssembly.

Later versions integrate the SMAUG-T and HAETAE reference implementations compiled to WebAssembly from their KpqC C reference code.

### Rust to WASM

The Quantum Vault core library compiles to WASM via `wasm-pack`. The AES-256-GCM and Shamir Secret Sharing layers run as compiled Rust in the browser.

### SMAUG-T and HAETAE in the Browser

Both algorithms have C reference implementations from the KpqC competition. These compile to WASM using **Emscripten**, and the Rust core library calls them through FFI bindings — which is exactly what the `kpqc.rs` backend in the existing architecture is designed for.

Considerations for the WASM compilation:
- Platform-specific randomness calls are routed to the browser's `crypto.getRandomValues`
- Memory footprint is managed for browser constraints
- KpqC reference code is portable C, which is favorable for Emscripten targets

### Hosting

The demo is a static Next.js export with a WASM bundle — no server-side processing required. Suitable for GitHub Pages, Render, or any static hosting.

---

## Project Structure

The project uses a Cargo workspace to separate the library (WASM-compilable) from the CLI binary, with the web demo as a standalone frontend application:

```
quantum-vault/
├─ Cargo.toml              ← workspace root
│
├─ crates/
│   ├─ qv-core/            ← core crypto library (compiles to WASM)
│   │   ├─ Cargo.toml      ← features: dev-backend (default), kpqc-native, kpqc-wasm, wasm
│   │   ├─ build.rs        ← compiles SMAUG-T + HAETAE C libs (kpqc-native only)
│   │   └─ src/
│   │       ├─ lib.rs
│   │       ├─ encrypt.rs
│   │       ├─ decrypt.rs
│   │       ├─ container.rs
│   │       ├─ shamir.rs
│   │       ├─ wasm.rs     ← wasm-bindgen exports (--features wasm)
│   │       └─ crypto/
│   │           ├─ mod.rs
│   │           ├─ kem.rs
│   │           ├─ signature.rs
│   │           └─ backend/
│   │               ├─ mod.rs
│   │               ├─ dev.rs
│   │               ├─ kpqc.rs      ← feature-gated: native / wasm / stub
│   │               └─ kpqc_ffi.rs ← extern "C" wrappers (kpqc-native only)
│   │
│   └─ qv-cli/             ← CLI binary
│       ├─ Cargo.toml
│       └─ src/
│           └─ main.rs     ← --backend dev|kpqc flag
│
├─ vendor/                  ← (gitignored) C reference implementations
│   ├─ smaug-t/             ←   extracted SMAUG-T reference implementation
│   └─ haetae/              ←   extracted HAETAE reference implementation
│
├─ web-demo/                ← Next.js interactive demo
│   ├─ package.json
│   ├─ src/
│   └─ public/
│
├─ docs/
│   ├─ architecture.md
│   ├─ container-format.md
│   └─ demo-preview.png
│
├─ LICENSE
└─ .gitignore
```

---

## CLI Usage

Generate a KEM + signature keypair with the dev backend:
```sh
qv keygen --out-dir ./keys --name alice
```

Encrypt a file for 3 recipients with a 2-of-3 threshold:
```sh
# First generate a key per recipient:
qv keygen --out-dir ./keys --name alice
qv keygen --out-dir ./keys --name bob
qv keygen --out-dir ./keys --name carol

# Then encrypt (comma-separated KEM public key files, read as base64):
qv encrypt \
  --in secret.pdf \
  --out secret.qvault \
  --pubkeys "$(cat keys/alice.kem.pub),$(cat keys/bob.kem.pub),$(cat keys/carol.kem.pub)" \
  --threshold 2 \
  --sign-key keys/alice.sig.priv
```

Decrypt with any 2 of the 3 private keys:
```sh
qv decrypt \
  --in secret.qvault \
  --out recovered.pdf \
  --privkeys "$(cat keys/alice.kem.priv),$(cat keys/bob.kem.priv)" \
  --verify-key keys/alice.sig.pub
```

The `--backend` flag selects the crypto backend (`dev` by default; `kpqc`
requires the `kpqc-native` or `kpqc-wasm` feature to be compiled in):
```sh
# Show which backend is active:
qv keygen --backend dev
```

---

## Getting Started — Web Demo

The interactive web demo runs entirely in the browser — no server required.

### Prerequisites

- Node.js ≥ 18
- npm ≥ 9

### Install and run

```bash
cd web-demo
npm install
npm run dev
# Open http://localhost:3000
```

### Run tests

```bash
cd web-demo
npm run test          # run all tests once (18 tests in 2 suites)
npm run test:watch    # watch mode
```

### Build for production

```bash
cd web-demo
npm run build   # Next.js production build
npm run start   # serve locally
```

### Optional: WASM build (requires Rust + wasm-pack)

```bash
# Install wasm-pack (one-time)
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Build the WASM package into public/wasm-pkg/
cd web-demo
npm run wasm:build
```

Once built, swap the backend in [web-demo/src/crypto/index.ts](web-demo/src/crypto/index.ts) — one import line change, nothing else.

---


The cryptographic implementation uses a **pluggable backend architecture**.

The application calls stable Rust trait interfaces (`encapsulate`/`decapsulate`, `sign`/`verify`) rather than binding directly to a single implementation. This allows:

- Easier testing with a development backend
- Cleaner separation of application logic and cryptographic primitives
- Future integration with real KpqC and NIST implementations
- Safer evolution of the codebase as algorithms mature

### Container Format

The `.qvault` container format is documented in `docs/container-format.md`. Getting this right is critical — versioning, authenticated metadata, and forward compatibility are where most real-world crypto tools encounter problems. The container design prioritizes:

- Explicit version fields for format evolution
- Authenticated metadata so tampering is detectable before decryption
- Clean separation of encrypted payload, protected shares, and signature data

### Shamir Secret Sharing

The Shamir implementation requires particular care around:

- Side-channel resistance during polynomial evaluation
- Share validation to detect corrupted or malicious shares before reconstruction
- Proper use of a finite field (GF(256) or a prime field) with no information leakage from partial share sets

---

## Current Development Status

Completed:

- AES-256-GCM file encryption
- Shamir Secret Sharing over GF(2^8) with duplicate-index and zero-index validation
- Container serialization with `kem_algorithm` + `sig_algorithm` metadata fields and AAD-protected AES-GCM
- Pluggable backend architecture (`dev-backend`, `kpqc-native`, `kpqc-wasm` feature flags)
- CLI (`qv keygen / encrypt / decrypt`) with `--backend dev|kpqc` flag; key files created with `0600` permissions
- WASM bridge for the browser demo (TypeScript fallback included)
- `build.rs` for SMAUG-T + HAETAE C compilation (activated by `kpqc-native`) with correct source paths, mode defines, and `randombytes_shim.c` OS entropy
- `kpqc_ffi.rs` — safe Rust wrappers with correct SMAUG-T + HAETAE symbol names, sizes, and HAETAE 7-arg API
- Feature-gated `kpqc.rs` — native FFI / WASM stub / no-op stub automatically selected
- Full adversarial security audit (20 findings resolved; see commit history)
- **Interactive web demo** (Next.js, Tailwind, Framer Motion):
  - Mock backend with real AES-256-GCM and real GF(256) Shamir (18 tests passing)
  - 52-card deck visualization with card flip, key scatter, lock/unlock, seal animations
  - Shamir threshold controls (N and T sliders)
  - Algorithm showcase carousel (CryptoZoo) with 6 algorithm cards
  - Fully responsive, accessible, no image assets
  - Easter egg: type `meow` for cat mode
  - WASM backend swap-in point documented

In progress / remaining:

- Vendor the KpqC reference C implementations (`vendor/smaug-t/`, `vendor/haetae/`)
- SMAUG-T / HAETAE WASM backend (swap into demo's `crypto/index.ts`)
- Hybrid mode (KpqC + NIST algorithm support)
- Formal test vectors

---

## Security Notice

Quantum Vault is currently an **experimental research project** and should not be considered production-ready.

Before production use the project would require:

- Formal cryptographic review
- Constant-time verification where relevant
- Test vectors for all cryptographic operations
- Container format validation and fuzzing
- Secure key lifecycle handling
- Interoperability testing for PQ backends

---

## License

MIT
