# Quantum Vault — Web Demo

An interactive browser demo that visualises every layer of the Quantum Vault cryptographic stack using a bank vault of 9 safety deposit boxes (3×3 grid).

> **v5.1 — KpqC browser artifacts.** SMAUG-T Level 1 key encapsulation and
> HAETAE Mode 2 signing run in WebAssembly reproduced from the pinned public
> reference-source archives recorded in `wasm/PROVENANCE.md`. AES-GCM and PBKDF2
> use Web Crypto, and Shamir sharing is TypeScript. The active pipeline has no
> mock KEM/signature or HMAC substitute.

---

## Quick Start

```bash
# from the web-demo/ directory
npm ci
npm run dev
# open http://localhost:5173
```

Requires Node 22.19+, 24, or 26+. CI runs web checks on Node 22, 24 and 26; the
Linux Chromium job uses Node 24.

---

## Demo Box Passwords

Three boxes are pre-sealed on first visit. Any two of the three passwords unlock each box.

| Box | Password 1 | Password 2 | Password 3 |
|-----|-----------|-----------|-----------|
| 03 | `ruby` | `emerald` | `diamond` |
| 06 | `fortress` | `bastion` | `citadel` |
| 09 | `monday` | `tuesday` | `wednesday` |

The passwords are also shown in the hint banner and the **"How this box works"** walkthrough panel on the demo page itself.

---

## Running Tests

```bash
npm run test          # Vitest unit tests and publisher request controls
npm run test:watch    # watch mode

npm run test:e2e:install   # one-time: download the Playwright Chromium build
npm run test:e2e           # run the browser end-to-end suite (Playwright)
```

Unit coverage (Vitest) includes:
- `src/crypto/__tests__/utils.test.ts` — base64 codec, byte helpers, text encode/decode
- `src/crypto/__tests__/shamir.test.ts` — GF(2⁸) Shamir split/reconstruct, threshold behaviour
- `src/crypto/__tests__/pipeline.test.ts` — full seal/open pipeline with mocked WASM modules
- `src/crypto/__tests__/keywrap.test.ts` — cleanup on KEM/wrapping failure paths
- `src/vault/__tests__/file.test.ts` — `.qvault` serialise / validate / tamper-reject
- `src/vault/__tests__/state.test.ts` — persisted-state bounds and validation
- `src/__tests__/signature-trust.test.ts` — embedded-key trust-boundary text controls

`tests/*.node.mjs` separately checks toolchain identities, deployment-request
isolation, active WASM exports/sizes and workflow permissions/control flow.

End-to-end coverage (Playwright, `e2e/*.spec.ts`) builds and serves the production
bundle, then drives a real Chromium browser through the active KpqC WASM
pipeline—no mocks:
- demo boxes seal on load and render (9 boxes, 3 pre-sealed)
- two correct passwords reconstruct and reveal the secret (any 2-of-3 pair)
- one correct / two wrong passwords stay below threshold → **ACCESS DENIED**, secret never shown
- seal a fresh secret into an empty box, then reopen it (full round-trip)

Both suites run in `.github/workflows/deploy-pages.yml`, alongside Rust application tests and binary/hash consistency checks. Browser execution of the committed WASM does not establish reproducible source-to-binary provenance.

---

## Project Structure

```
web-demo/
├── index.html
├── vite.config.ts
├── vitest.config.ts
├── tsconfig.json
├── package.json
├── public/
│   ├── smaug.wasm          ← compiled SMAUG-T Level 1 (committed)
│   └── haetae.wasm         ← compiled HAETAE Mode 2 (committed)
└── src/
    ├── main.ts             ← entry point; awaits initCrypto() before vault init
    ├── crypto/
    │   ├── init.ts         ← parallel WASM module initialisation
    │   ├── smaug.ts        ← SMAUG-T Level 1 WASM wrapper
    │   ├── haetae.ts       ← HAETAE Mode 2 WASM wrapper
    │   ├── keywrap.ts      ← SMAUG-T KEM + PBKDF2 share wrapping
    │   ├── pipeline.ts     ← sealMessage / openBox orchestration
    │   ├── aes.ts          ← AES-256-GCM via Web Crypto API
    │   ├── shamir.ts       ← Shamir SSS over GF(2⁸)
    │   ├── utils.ts        ← base64, text codecs, byte helpers
    │   ├── signature.ts    ← re-export shim for haetae.ts
    │   └── wasm/
    │       ├── smaug.js    ← Emscripten JS loader (committed)
    │       ├── smaug.d.ts
    │       ├── haetae.js   ← Emscripten JS loader (committed)
    │       └── haetae.d.ts
    ├── vault/
    │   ├── demo.ts         ← generates demo boxes on first visit
    │   ├── file.ts         ← .qvault import/export validation
    │   └── state.ts        ← localStorage persistence / serialisation
    ├── ui/
    │   ├── wall.ts
    │   ├── panel.ts
    │   ├── pipeline-ui.ts
    │   └── reveal.ts
    └── styles/
        └── vault.css
```

---

## Cryptographic Pipeline

### Seal (deposit)

```
AES-256-GCM  →  Shamir split  →  SMAUG-T wrap  →  HAETAE sign
```

1. **AES-256-GCM** — encrypt plaintext with a random 256-bit key
2. **Shamir split** — split the 32-byte AES key into 3 shares, threshold = 2
3. **SMAUG-T wrap** (×3) — fresh SMAUG-T keypair per participant; encapsulate share; seal SK with PBKDF2(password)
4. **HAETAE sign** — fresh signing keypair; sign canonical JSON containing the
   `SealedBox` ciphertext, timestamp, nonce, embedded verification key and every
   cryptographic wrapped-share field (but not outer export labels/metadata)

### Open (retrieve)

```
HAETAE verify  →  SMAUG-T unlock  →  Shamir reconstruct  →  AES-256-GCM
```

1. **HAETAE verify** — reject invalid signatures under the key included in the container
2. **SMAUG-T unlock** (for each password) — PBKDF2 → decrypt SK → decapsulate → recover Shamir share
3. **Shamir reconstruct** — two valid shares recover the key; one produces an
   unauthenticated candidate that AES-GCM normally rejects
4. **AES-256-GCM** — decrypt ciphertext; wrong key → DOMException

### Signature trust boundary

The included signing key is not independently authenticated. Changes with the
old signature fail, but anyone can generate a new HAETAE keypair and re-sign
changed public container data. This does not recover the encrypted shares or
secret. A successful signature check or file import does not authenticate the
original sender. Stronger authenticity requires a key trusted outside the
replaceable container; this demo implements no such pin or PKI binding.

The real shipped-WASM positive and negative controls are in
`e2e/signature-trust.spec.ts`: old-signature edits and key-only replacement fail;
new-key re-signing verifies, while verification under the original key rejects
it. The unchanged encrypted contents still open with the legitimate passwords.
Run with `npx playwright test e2e/signature-trust.spec.ts --workers=1 --retries=0`.
The Node pipeline tests mock KpqC and do not replace this browser control or
establish reproducible source-to-WASM provenance.

[NIST SP 800-89](https://csrc.nist.gov/pubs/sp/800/89/final) distinguishes
signature verification from assurance of a key owner's identity. This is a
general trust principle, not a claim that HAETAE is a FIPS-approved algorithm.

---

## Building for Production

```bash
npm run build   # TypeScript type-check + Vite production build → dist/
```

The build uses the native TypeScript 7 compiler. ESLint and other JavaScript-API
consumers use Microsoft's side-by-side TypeScript 6 wrapper until their peer
ranges include TypeScript 7; `npm run check:typescript` guards both identities
and verifies strict compiler rejection controls.

Deployed to GitHub Pages via `.github/workflows/deploy-pages.yml`.

`npm run deploy` requests that workflow on the remote `main` branch using authenticated GitHub CLI access. Both the Rust and web application gates must pass before deployment. It does not publish a local `dist/` directory; the request controls in `npm test` replace only the external GitHub command and never dispatch a workflow.

---

## WASM Modules

The `.wasm` binaries and Emscripten JS loaders are committed. The authoritative
verification path rebuilds from the immutable archives and compares all four
outputs without replacing the shipped artifacts:

```bash
# From the repository root, after separately capturing the exact archives and
# digest-pinned compiler image named in wasm/PROVENANCE.md:
bash wasm/build.sh --reproduce \
  --smaug-archive /absolute/path/smaug.tar.gz \
  --haetae-archive /absolute/path/haetae.zip \
  --scratch-root /absolute/path/to/writable-scratch
```

The generic `bash wasm/build.sh` path is a development recipe for separately
supplied vendor directories; it does not reproduce the committed pair and must
not be used to overwrite it. See `wasm/PROVENANCE.md` and
`wasm/reproduction.json` for source identities, archive hashes, compiler digest,
artifact-specific commands and expected outputs.

---

## Timing Harness

A timing side-channel analysis tool is available at `timing-harness.html`. It measures:

- **HAETAE signing** timing distribution across multiple iterations
- Timer resolution (requires Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy headers)
- Statistical analysis: min, max, mean, standard deviation, coefficient of variation

To use:
1. Run `npm run dev` (Vite dev server includes required COOP/COEP headers)
2. Open `http://localhost:5173/timing-harness.html`
3. Click **Run Timing Test**
4. Export results as CSV for further analysis

A low coefficient of variation does **not** establish constant-time behavior.
Interpretation requires raw interleaved samples, environment details, a
predefined decision rule and a negative control; any detected difference still
requires analysis before it can be called exploitable.

---

## License

MIT — see root [`LICENSE`](../LICENSE).
