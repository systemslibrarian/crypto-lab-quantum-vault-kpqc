# crypto-lab-quantum-vault-kpqc

## What It Is
Quantum Vault is a browser demo that combines AES-256-GCM, Shamir SSS / GF(2⁸), SMAUG-T (스마우그-T) KEM, and HAETAE (해태) signature in one sealing/opening pipeline. It is built to show how a secret can be encrypted once, split into threshold shares, and opened only when enough valid shares are recovered. SMAUG-T handles post-quantum key encapsulation for per-share wrapping, and HAETAE verifies container integrity before decryption. The security model is hybrid: symmetric encryption plus post-quantum asymmetric primitives with threshold reconstruction.

## When to Use It
- Browser-based crypto education and demos: It shows each stage (AES, Shamir, KEM, signature) in a visible, testable workflow.
- Threshold recovery experiments: It is a direct fit when you need 2-of-3 style reconstruction behavior for short secrets.
- Post-quantum interoperability prototyping: It helps validate SMAUG-T and HAETAE integration paths in client-side WASM.
- Local, no-server cryptographic walkthroughs: It fits scenarios where operations should run in-browser without backend round-trips.
- Do NOT use this for production secret management: It is an educational/experimental demo and does not claim production hardening.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-quantum-vault-kpqc](https://systemslibrarian.github.io/crypto-lab-quantum-vault-kpqc/)**

The demo lets you open pre-sealed boxes, seal new short messages, and test 2-of-3 password recovery behavior end to end. You can switch language (EN/한국어), import/export individual containers, and import/export full vault state. The visible controls include vault actions (Export vault, Import vault, Clear vault, Reset to demo) and password entry fields for threshold recovery.

## What Can Go Wrong
- **Too few shares means permanent loss.** Shamir reconstruction needs at least the threshold number of valid shares; lose more than `n − t` and the secret is gone for good, with no fallback because nothing else holds the key.
- **AES-GCM nonce reuse is catastrophic.** Reusing a (key, nonce) pair under AES-256-GCM leaks the XOR of plaintexts and lets an attacker forge the authentication tag, breaking both confidentiality and integrity.
- **Plain Shamir does not detect bad shares.** Basic secret sharing has no built-in cheater detection, so a corrupted or maliciously altered share can silently produce a wrong reconstruction unless a verifiable scheme is layered on top.
- **Threshold choice is a security/availability tradeoff.** A low threshold makes recovery easy but also makes compromise easy (fewer shares to steal); a high threshold resists compromise but raises the risk of being unable to reassemble enough shares.
- **KpqC primitives are newer than the NIST FIPS picks.** SMAUG-T and HAETAE come from the Korean KpqC standardization effort and have had less cross-implementation scrutiny than ML-KEM/ML-DSA, so parameter or encoding changes between revisions can break interoperability.

## Real-World Usage
- **Shamir Secret Sharing** underpins root-key custody in systems such as HashiCorp Vault's unseal keys, HSM key-backup ("M-of-N") cards, and split-key recovery for high-value secrets.
- **AES-256-GCM** is the default authenticated-encryption mode across TLS 1.3, disk and database encryption, and cloud KMS envelope encryption.
- **The KpqC competition** is South Korea's national post-quantum standardization process; SMAUG-T (KEM) and HAETAE (signature) are among its selected lattice-based schemes, mirroring the role ML-KEM and ML-DSA play in NIST's portfolio.
- **Threshold + envelope patterns** like the one shown here — encrypt once with a symmetric key, then split or wrap that key — are how cloud KMS and cryptocurrency custody services protect master keys.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc
cd crypto-lab-quantum-vault-kpqc/web-demo
npm install
npm run dev
```

## Related Demos
- [crypto-lab-shamir-gate](https://systemslibrarian.github.io/crypto-lab-shamir-gate/) — Shamir Secret Sharing and Lagrange interpolation, the threshold-split half of this vault.
- [crypto-lab-silent-tally](https://systemslibrarian.github.io/crypto-lab-silent-tally/) — secret sharing applied to private aggregation over a finite field.
- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — ML-KEM (FIPS 203), the NIST lattice KEM counterpart to SMAUG-T.
- [crypto-lab-scloud-vault](https://systemslibrarian.github.io/crypto-lab-scloud-vault/) — another LWE-based KEM with ternary secrets, for comparison with SMAUG-T.
- [crypto-lab-threshold-mldsa](https://systemslibrarian.github.io/crypto-lab-threshold-mldsa/) — distributed, threshold post-quantum signing, pairing threshold ideas with PQ signatures.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
