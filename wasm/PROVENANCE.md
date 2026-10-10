# Distributed WASM evidence

`provenance.json` records SHA-256 fingerprints of the tracked SMAUG-T and HAETAE artifacts used by the web demo. These match the adjacent tracked `.sha256` files. A matching fingerprint identifies bytes; it does not establish which upstream C source or compiler produced them.

The readable `wasm/src` wrappers and `wasm/build.sh` refer to source directories that are not tracked:

- `wasm/vendor/smaug-t/reference_implementation`
- `wasm/vendor/haetae/HAETAE-1.1.2/reference_implementation`

The upstream inputs that produced the shipped browser binaries and the original Emscripten environment remain unknown. Historical Git links now identify two authenticated upstream archive candidates, described below; their relationship to the active browser binaries has not been established. The version-like HAETAE directory name alone is not an authenticated source pin. Do not fill the shipped artifacts' provenance fields from a candidate or claim that a successful web-demo test reproduces the cryptographic implementation.

`bash wasm/build.sh` reports absent directories, missing or unreadable declared C inputs, and the wrappers' required headers as UNREAD and exits 2 before compiling either algorithm or creating output directories. This is an incomplete build, not a failed cryptographic test. Supplying files alone does not establish their provenance or guarantee compilation. Before a reproducibility claim, record immutable upstream source identities, compiler/toolchain versions and flags, rebuild both artifacts, retain logs and compare bytes. Differences need investigation; they do not alone prove incorrect cryptography.

The build script's optimization flags and “constant-time hardened” wording are not evidence of a constant-time audit. This maintenance change does not modify binaries, wrappers, deployment triggers or permissions.

## Authenticated historical candidates

The lab's [commit `4f3cde61`](https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc/tree/4f3cde61189372acdb572fd234fb380df2349443/vendor) records Git links for `vendor/smaug-t` and `vendor/haetae`. They were removed by [the subsequent browser implementation commit](https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc/commit/5ed9181e870e781c1ceefe8354658d781ad8d449). No `.gitmodules` file supplies their remote URLs. Independently, both linked commit IDs resolve in the official repositories linked by the [KpqC final implementation page](https://kpqc.or.kr/contents/03_exhibit/sub_03.html):

| Candidate | Immutable upstream commit | Archive SHA-256 |
|---|---|---|
| SMAUG-T 1.1.1 | [bbc463cd788eae36c6d155cef667ac9dbd9054cd](https://github.com/CryptoLabInc/SMAUG-T/commit/bbc463cd788eae36c6d155cef667ac9dbd9054cd) | `d7213f1618282cbcb4090abe808a164f9689062f2b65b34fd86496b9923200d7` |
| HAETAE 1.1.2 | [743c31df48183fc8c8a39a4f50a634da1c4af03a](https://github.com/CryptoLabInc/HAETAE/commit/743c31df48183fc8c8a39a4f50a634da1c4af03a) | `9b69afb55ed96a20d9626b3ea729c291f9e4bfd8d880b740fcb30f6955c4ca72` |

`historical-source-candidates.json` retains the Git blob IDs, immutable download links, capture time and limits. Each downloaded archive was checked against its Git blob identity and SHA-256. These are historical candidate inputs, not an original browser-build attestation.

On 2026-10-10, copying their unmodified reference files into the build script's expected layout and running its PR #14 version with the available `/opt/homebrew/opt/emscripten/bin/emcc` (actual version `6.0.10-git`) failed with exit 1 because SMAUG-T's `src/io.c` is absent. Its `include/kem.h`, which the tracked wrapper includes, is also absent from the archive. No JS or WASM artifacts were produced. The tracked nested `original/quantum-vault-kpqc-main.zip` contains wrappers and binaries, but no vendor source; SHA-256 `6825119efa653d47f49e13508c64588c9d10804be8148c5e8aea2a29ba693a31` identifies that archive. `original/haetae.wasm` matches the active HAETAE bytes, which is distribution identity, not an additional reproduction.

The current preflight correctly rejects those same candidate inputs with exit 2 before invoking the compiler or creating `dist`. Recover the browser build's actual missing or modified vendor files, their immutable identities, and the original compiler/flags before claiming correspondence. The documentation's Emscripten 5.0.3 recipe is a recorded claim; the available 6.0.10-git compiler is a separately measured environment. Neither proves which compiler produced the shipped bytes.

A separate HAETAE-only diagnostic compiled its unmodified candidate sources with the tracked HAETAE source list, wrapper and flags, using an isolated compiler cache and the measured 6.0.10-git toolchain. It exited 0, but neither artifact matches the shipped bytes: candidate WASM SHA-256 `640c8e5fa0ece70e6ae9cc8e9b07d959b836334c964f6a57bd3f0da5fc441821` versus shipped `9510374922d602ec19da80c9ce4eea1262da45920425b5e6ce6c953ce8d3652e`; candidate loader `de22a7456aff06afedcf9472f0f6b4f5b36b585e3b55b730f8061fba4875c81d` versus shipped `e0d5aed3080b4f4629aa283f7b8a3b52722671deeaf9f96cd9c0107203316a5a`. The machine-readable record retains the sizes and comparison. This partial diagnostic did not compile SMAUG-T, modify any active artifact or establish the original compiler. The mismatch alone does not identify a cryptographic defect.

## Repeatable preflight controls

```sh
bash -n wasm/build.sh
python3 -B -m unittest discover -s wasm/tests -v
```

The eight tests cover absent directories, incomplete or unreadable inputs for either algorithm, missing wrapper headers, missing compiler, successful fixture plumbing and failures in either compiler call. Negative controls assert that incomplete input invokes no compiler and creates no output directory. The positive fixture compiler writes explicitly artificial outputs; these tests do not compile cryptographic source or establish binary reproduction. The existing Pages PR gate runs this suite before the application checks. No deployment trigger or permission is changed.
