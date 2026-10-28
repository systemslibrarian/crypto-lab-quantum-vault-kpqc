# crypto-lab-quantum-vault-kpqc

## What It Is
Quantum Vault is a browser demo that combines AES-256-GCM, Shamir SSS / GF(2⁸), SMAUG-T (스마우그-T) KEM, and HAETAE (해태) signature in one sealing/opening pipeline. It is built to show how a secret can be encrypted once, split into threshold shares, and opened only when enough valid shares are recovered. SMAUG-T handles post-quantum key encapsulation for per-share wrapping, and HAETAE checks the signature under the container’s included, unpinned key before decryption; that does not authenticate the original sender. The security model is hybrid: symmetric encryption plus post-quantum asymmetric primitives with threshold reconstruction. A plain-language **"How this box works"** walkthrough tells the four-primitive envelope story in order, per-step narration lights up as each pipeline stage runs, and a Shamir key-strip visualization shows the real 32-byte AES key splitting into 3 shares and re-forming from any 2 (or producing an unauthenticated candidate from just 1). On open, real recovered share strips combine into the reconstructed key. There is no independent original-key reference or per-byte comparison: copying the reconstruction would not supply evidence. The strip is confirmed only by successful AES-GCM authenticated decryption; two recovered shares alone cannot establish successful opening. Failed authentication leaves it unconfirmed, and one share is below threshold. An "inside step 3" mini-diagram separates the password-protected secret-key path from KEM encapsulation/decapsulation and explains that defeating either route can expose a share; their strengths are not additive. A small 2-D lattice sketch introduces the assumptions motivating the post-quantum design without presenting them as proof. Inline glossary tooltips introduce KEM, Shamir/GF(2⁸), "lattice-based", and sign-vs-verify for newcomers; a classical-vs-post-quantum toggle and a one-click tamper demo make the "harvest now, decrypt later" motivation and the confidentiality-vs-integrity failure distinction concrete; expert-facing "when to use each primitive" reference cards are gated behind a **Go deeper** reveal so the first-scroll path stays focused on the interactive core.

## Exhibits
1. **Vault wall** — 9 safety-deposit boxes; three pre-sealed on first visit with real KpqC crypto, openable with any 2 of 3 passwords.
2. **How this box works** — persistent, ordered envelope walkthrough (AES lock → Shamir split → SMAUG-T per-share seal → HAETAE signature) whose sentences light up in sync with the live pipeline.
3. **Seal / open pipeline** — animated step pills with per-step plain-language narration, driven by the real crypto outcome, not a fixed script.
4. **Shamir key-strip** — real AES key and three shares during seal; recovered shares and reconstructed bytes during open. Successful authenticated decryption provides confirmation, not matching a copied strip. No original key is stored to supply an open-side comparison. A below-threshold attempt remains unconfirmed, as does an AES authentication failure even with two recovered shares.
5. **Inside step 3: two sequential layers** — a mini-diagram separating what your password does (PBKDF2 → unlock the keyholder's SMAUG-T secret key) from what the KEM does (encapsulate/decapsulate → recover the wrapping key), while making clear that compromising either route can expose the share.
6. **2-D lattice sketch** — a deliberately rough visual analogy for the structured high-dimensional lattice assumptions behind SMAUG-T, labelled as motivation rather than a security proof.
7. **Glossary tooltips** — click-to-expand newcomer definitions with one-line analogies for KEM, Shamir sharing / GF(2⁸), lattice-based hardness, and signature vs. verify.
8. **Classical vs. post-quantum** — a toggle tied to the SMAUG-T step comparing RSA/ECDH's known quantum weakness with the lattice assumptions for which no efficient quantum attack is currently known.
9. **Two failure modes, distinctly** — a wrong password turns just that keyholder's SMAUG-T pill amber ("share unavailable — N of 2 needed"); a tamper demo button flips a ciphertext byte and turns the HAETAE-verify pill red, stopping before any share is tried.
10. **Go deeper (gated reference)** — expert-facing "when to use each primitive / what breaks if you don't" cards revealed on demand, keeping the first scroll on try-a-box → watch-the-pipeline → read-the-story.
11. **Vault management** — export/import individual `.qvault` containers and full vault state, reset to demo, and an EN/한국어 language toggle.

## When to Use It

Reconstruction evidence is checked by `web-demo/src/crypto/__tests__/pipeline.test.ts`: tests retain a separate seal-side key only as an independent test oracle, and verify successful, below-threshold and AES-failure outcomes. Their KEM/signature adapters are explicitly mocked; AES-GCM, PBKDF2 and Shamir run for real. `web-demo/e2e/reconstruction-evidence.spec.ts` uses the actual shipped SMAUG-T/HAETAE WASM, including a correctly re-signed corrupt ciphertext: two recovered shares must still leave AES failed and the key unconfirmed. It also checks English/Korean disclosures at desktop, 380px and 320px. Run `npm test`, `npm run lint -- --max-warnings=0`, `npm run build` and `npm run test:e2e -- --retries=0` from `web-demo`. These controls do not establish WASM source/compiler provenance or a full security audit.
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
- **AES-GCM nonce reuse is catastrophic.** Reusing a (key, nonce) pair under AES-256-GCM leaks relationships between plaintexts and enables practical forgeries, breaking both confidentiality and integrity.
- **Plain Shamir does not detect bad shares.** Basic secret sharing has no built-in cheater detection, so a corrupted or maliciously altered share can silently produce a wrong reconstruction unless a verifiable scheme is layered on top.
- **Threshold choice is a security/availability tradeoff.** A low threshold makes recovery easy but also makes compromise easy (fewer shares to steal); a high threshold resists compromise but raises the risk of being unable to reassemble enough shares.
- **KpqC competition selection is not publication as a standard.** SMAUG-T and HAETAE are final KpqC competition algorithms, but the [April 2026 status notice](https://kpqc.or.kr/contents/03_exhibit/board.html?board_id=board_competition&mode=view&no=12) says SMAUG-T was proposed for Korean-standard development while HAETAE remained under review. Neither selection alone is a published Korean Standard, and parameters or encodings can still change during standardization.

## Real-World Usage
- **Shamir Secret Sharing** underpins root-key custody in systems such as HashiCorp Vault's unseal keys, HSM key-backup ("M-of-N") cards, and split-key recovery for high-value secrets.
- **AES-GCM** is a widely deployed AEAD in TLS 1.3 cipher suites, storage systems, databases, and cloud envelope-encryption designs; exact defaults vary by product and platform.
- **The KpqC competition** [selected SMAUG-T (KEM) and HAETAE (signature) as final lattice-based algorithms in 2025](https://kpqc.or.kr/contents/03_exhibit/board.html?board_id=board_competition&mode=view&no=9). In April 2026, KpqC reported SMAUG-T among the KEM proposals submitted for Korean-standard development and HAETAE among the signature algorithms still under review; that status is distinct from NIST's already published ML-KEM and ML-DSA standards.
- **Threshold + envelope patterns** like the one shown here — encrypt once with a symmetric key, then split or wrap that key — are how cloud KMS and cryptocurrency custody services protect master keys.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc
cd crypto-lab-quantum-vault-kpqc/web-demo
npm ci
npm run dev
```

## Related Demos
- [crypto-lab-shamir-gate](https://systemslibrarian.github.io/crypto-lab-shamir-gate/) — Shamir Secret Sharing and Lagrange interpolation, the threshold-split half of this vault.
- [crypto-lab-silent-tally](https://systemslibrarian.github.io/crypto-lab-silent-tally/) — secret sharing applied to private aggregation over a finite field.
- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — ML-KEM (FIPS 203), the NIST lattice KEM counterpart to SMAUG-T.
- [crypto-lab-scloud-vault](https://systemslibrarian.github.io/crypto-lab-scloud-vault/) — another LWE-based KEM with ternary secrets, for comparison with SMAUG-T.
- [crypto-lab-threshold-mldsa](https://systemslibrarian.github.io/crypto-lab-threshold-mldsa/) — distributed, threshold post-quantum signing, pairing threshold ideas with PQ signatures.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
