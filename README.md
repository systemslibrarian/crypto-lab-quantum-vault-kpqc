# Quantum Vault — v5.1

[![CI](https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc/actions/workflows/ci.yml)
[![Deploy](https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc/actions/workflows/deploy-pages.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What It Is
Quantum Vault is a browser demo that combines AES-256-GCM, Shamir SSS / GF(2⁸), SMAUG-T (스마우그-T) KEM, and HAETAE (해태) signature in one sealing/opening pipeline. It is built to show how a secret can be encrypted once, split into threshold shares, and opened only when enough valid shares are recovered. SMAUG-T handles post-quantum key encapsulation for per-share wrapping, and HAETAE verifies container integrity before decryption. The security model is hybrid: symmetric encryption plus post-quantum asymmetric primitives with threshold reconstruction.

## When to Use It
- Browser-based crypto education and demos: It shows each stage (AES, Shamir, KEM, signature) in a visible, testable workflow.
- Threshold recovery experiments: It is a direct fit when you need 2-of-3 style reconstruction behavior for short secrets.
- Post-quantum interoperability prototyping: It helps validate SMAUG-T and HAETAE integration paths in client-side WASM.
- Local, no-server cryptographic walkthroughs: It fits scenarios where operations should run in-browser without backend round-trips.
- Not for production secret management: It is an educational/experimental demo and does not claim production hardening.

## Live Demo
[systemslibrarian.github.io/crypto-lab-quantum-vault-kpqc](https://systemslibrarian.github.io/crypto-lab-quantum-vault-kpqc/)

The demo lets you open pre-sealed boxes, seal new short messages, and test 2-of-3 password recovery behavior end to end. You can switch language (EN/한국어), import/export individual containers, and import/export full vault state. The visible controls include vault actions (Export vault, Import vault, Clear vault, Reset to demo) and password entry fields for threshold recovery.

## How to Run Locally
```bash
git clone https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc.git
cd crypto-lab-quantum-vault-kpqc/web-demo
npm install
npm run dev
```

No environment variables are required for local development in the current setup.

## Part of the Crypto-Lab Suite
This demo is one project in the Crypto-Lab suite: https://systemslibrarian.github.io/crypto-lab/

Whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31
