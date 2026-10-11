# Distributed WASM evidence

`provenance.json` records source correspondence and SHA-256 fingerprints of the tracked SMAUG-T and HAETAE artifacts used by the web demo. Fingerprints alone identify bytes; the separate clean builds establish correspondence with the pinned source recipe.

The readable `wasm/src` wrappers and `wasm/build.sh` refer to source directories that are not tracked:

- `wasm/vendor/smaug-t/reference_implementation`
- `wasm/vendor/haetae/HAETAE-1.1.2/reference_implementation`

The original Emscripten environment remains unknown. On 2026-10-11, authenticated immutable upstream source and historical wrappers were recovered and cleanly compiled with a separately identified reproducing environment. Both active loaders and both active WASM files match exactly; the evidence and repeatable command are below. The earlier failed source candidates remain recorded in the historical section. The version-like HAETAE directory name alone is not an authenticated source pin. Do not fill the shipped artifacts' provenance fields from a candidate or claim that a successful web-demo test reproduces the cryptographic implementation.

`bash wasm/build.sh` reports absent directories, missing or unreadable declared C inputs, and the wrappers' required headers as UNREAD and exits 2 before compiling either algorithm or creating output directories. This is an incomplete build, not a failed cryptographic test. Supplying files alone does not establish their provenance or guarantee compilation. Before a reproducibility claim, record immutable upstream source identities, compiler/toolchain versions and flags, rebuild both artifacts, retain logs and compare bytes. Differences need investigation; they do not alone prove incorrect cryptography.

The build script's optimization flags and “constant-time hardened” wording are not evidence of a constant-time audit. This maintenance change preserves binaries and wrappers and adds source verification to the existing CI gate.

## Verified source correspondence (2026-10-11)

The [measured component report](reports/source-correspondence-20261011.json)
records exact byte matches for **both loaders and both active WASM files** at
lab SHA `a0a174e5783b94afe1b8d1775445725622b7d02f`. These application bytes
were preserved. [reproduction.json](reproduction.json) contains the complete
file inventory, SHA-256/Git blob identities, wrapper pins, commands, compiler
image digest, actual compiler source revision and expected output identities.

| Component | Authenticated source | Historical wrappers |
|---|---|---|
| SMAUG-T | [archived official predecessor, `2c039df23134a2de3c7aa86a4904c9a4734f9def`](https://github.com/hmchoe0528/SMAUG-T_public/tree/2c039df23134a2de3c7aa86a4904c9a4734f9def/reference_implementation), all 52 reference files | lab `fcff4c5d00e19a334a455a9a18deee01d8c3b61b`, including its `getentropy` RNG shim |
| HAETAE | [official archive at `743c31df48183fc8c8a39a4f50a634da1c4af03a`](https://github.com/CryptoLabInc/HAETAE/tree/743c31df48183fc8c8a39a4f50a634da1c4af03a), 36 reference C/header files | lab `5ed9181e870e781c1ceefe8354658d781ad8d449`, followed by the exact recorded ESM adapter from `7bc71c6935dcb25ba647a06400146fcd8aca509e` |

The SMAUG predecessor contains the previously missing `io.c` and `kem.h` and
the wrapper's actual namespace/API. The newer 1.1.1 archive is a different
implementation and remains a failed historical candidate. HAETAE's active
bytes use the earlier `-O2` wrapper, allocator/heap-view exports, 32 MiB initial
memory and 2 MiB stack. Its current development wrapper and `-O1` recipe target
a different historical artifact; they must not be substituted silently.

The reproducing environment is Linux amd64 Emscripten **5.0.3**, compiler
revision `285c424dfa9e83b03cf8490c65ceadb7c45f28eb`, in image
`emscripten/emsdk@sha256:7b5d14203bb4ef20da6f5b71b90c8f37ec09c2776d342efff3bc989ebf1aa873`.
Every C object is freshly compiled; the image's 1,913 system-library inputs are
copied unchanged to isolated scratch and checked before/after compilation.
This is an independently identified **reproducing** environment. The original
publisher's compiler remains `null`. Matching bytes do not prove constant-time
behavior, original author build provenance, algorithm security or complete
static-scanner coverage. `original/haetae.wasm` is only a duplicate distribution
artifact and remains separate from the two active runtime binaries.

Use an otherwise clean checkout with full lab history, an already captured
digest-pinned compiler image, and these two locally saved public archives:

```sh
# Download separately; the verifier itself performs no network requests.
curl --fail --location --proto '=https' --tlsv1.2 \
  'https://codeload.github.com/hmchoe0528/SMAUG-T_public/tar.gz/2c039df23134a2de3c7aa86a4904c9a4734f9def' -o /tmp/smaug.tar.gz
curl --fail --location --proto '=https' --tlsv1.2 \
  'https://raw.githubusercontent.com/CryptoLabInc/HAETAE/743c31df48183fc8c8a39a4f50a634da1c4af03a/HAETAE.zip' -o /tmp/haetae.zip
docker pull --platform linux/amd64 \
  emscripten/emsdk@sha256:7b5d14203bb4ef20da6f5b71b90c8f37ec09c2776d342efff3bc989ebf1aa873
bash wasm/build.sh --reproduce \
  --smaug-archive /tmp/smaug.tar.gz --haetae-archive /tmp/haetae.zip
```

Optional `--docker-context NAME` selects an existing local engine without
changing its global context; `--scratch-root DIR` selects its writable mount.
Scratch, actual compiler logs and comparison evidence are retained. The
command reads committed source and wrappers with Git, validates all archive
bytes before extracting, rejects incomplete/unsafe inputs and requires all
four current artifact identities. It mounts only fresh scratch, runs as an
unprivileged user with networking disabled, installs no lab dependencies,
executes no repository lifecycle scripts, and never replaces shipped output.
Dirty or moving source, unreadable/partial output and timeouts return nonzero.
A complete byte mismatch is exit 1; incomplete evidence is exit 2. Success is
exit 0 only after every stage and all four exact comparisons pass.

The existing application workflow runs the real source rebuild as a separate
read-only job. Both Pages deployment and Dependabot integration now require
that job **in addition to** their existing Rust and web checks. A distribution
fingerprint check or passing application suite cannot substitute for it.

## Historical candidate diagnostics (2026-10-10)

The lab's [commit `4f3cde61`](https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc/tree/4f3cde61189372acdb572fd234fb380df2349443/vendor) records Git links for `vendor/smaug-t` and `vendor/haetae`. They were removed by [the subsequent browser implementation commit](https://github.com/systemslibrarian/crypto-lab-quantum-vault-kpqc/commit/5ed9181e870e781c1ceefe8354658d781ad8d449). No `.gitmodules` file supplies their remote URLs. Independently, both linked commit IDs resolve in the official repositories linked by the [KpqC final implementation page](https://kpqc.or.kr/contents/03_exhibit/sub_03.html):

| Candidate | Immutable upstream commit | Archive SHA-256 |
|---|---|---|
| SMAUG-T 1.1.1 | [bbc463cd788eae36c6d155cef667ac9dbd9054cd](https://github.com/CryptoLabInc/SMAUG-T/commit/bbc463cd788eae36c6d155cef667ac9dbd9054cd) | `d7213f1618282cbcb4090abe808a164f9689062f2b65b34fd86496b9923200d7` |
| HAETAE 1.1.2 | [743c31df48183fc8c8a39a4f50a634da1c4af03a](https://github.com/CryptoLabInc/HAETAE/commit/743c31df48183fc8c8a39a4f50a634da1c4af03a) | `9b69afb55ed96a20d9626b3ea729c291f9e4bfd8d880b740fcb30f6955c4ca72` |

`historical-source-candidates.json` retains the Git blob IDs, immutable download links, capture time and limits. Each downloaded archive was checked against its Git blob identity and SHA-256. These are historical candidate inputs, not an original browser-build attestation.

On 2026-10-10, copying their unmodified reference files into the build script's expected layout and running its PR #14 version with the available `/opt/homebrew/opt/emscripten/bin/emcc` (actual version `6.0.10-git`) failed with exit 1 because SMAUG-T's `src/io.c` is absent. Its `include/kem.h`, which the tracked wrapper includes, is also absent from the archive. No JS or WASM artifacts were produced. The tracked nested `original/quantum-vault-kpqc-main.zip` contains wrappers and binaries, but no vendor source; SHA-256 `6825119efa653d47f49e13508c64588c9d10804be8148c5e8aea2a29ba693a31` identifies that archive. `original/haetae.wasm` matches the active HAETAE bytes, which is distribution identity, not an additional reproduction.

The preflight correctly rejects those same historical candidate inputs with exit 2 before invoking the compiler or creating `dist`. Recover the browser build's actual missing or modified vendor files, their immutable identities, and the original compiler/flags before claiming correspondence. The documentation's Emscripten 5.0.3 recipe is a recorded claim; the available 6.0.10-git compiler is a separately measured environment. Neither proves which compiler produced the shipped bytes.

A separate HAETAE-only diagnostic compiled its unmodified candidate sources with the tracked HAETAE source list, wrapper and flags, using an isolated compiler cache and the measured 6.0.10-git toolchain. It exited 0, but neither artifact matches the shipped bytes: candidate WASM SHA-256 `640c8e5fa0ece70e6ae9cc8e9b07d959b836334c964f6a57bd3f0da5fc441821` versus shipped `9510374922d602ec19da80c9ce4eea1262da45920425b5e6ce6c953ce8d3652e`; candidate loader `de22a7456aff06afedcf9472f0f6b4f5b36b585e3b55b730f8061fba4875c81d` versus shipped `e0d5aed3080b4f4629aa283f7b8a3b52722671deeaf9f96cd9c0107203316a5a`. The machine-readable record retains the sizes and comparison. This partial diagnostic did not compile SMAUG-T, modify any active artifact or establish the original compiler. The mismatch alone does not identify a cryptographic defect.

## Repeatable preflight controls

```sh
bash -n wasm/build.sh
python3 -B -m unittest discover -s wasm/tests -v
```

The thirteen tests cover absent directories, incomplete or unreadable inputs for either algorithm, missing wrapper headers, missing compiler, successful fixture plumbing, failures in either compiler call, zero-exit compilers with missing/partial/empty/symlink outputs, and pre-existing output preservation. Negative controls assert that incomplete input invokes no compiler and creates no output directory. The positive fixture compiler writes explicitly artificial outputs; these tests do not compile cryptographic source or establish binary reproduction. The existing Pages PR gate runs this suite before the application checks. No deployment trigger or permission is changed.

The build requires a fresh, absent `wasm/dist` path and preserves any existing output evidence by refusing to overwrite it (exit 2). Use a fresh source copy for a repeated build. After each compiler returns zero, both its loader and WASM must be nonempty, readable regular files without symlinks before the script proceeds. Missing outputs remain incomplete (exit 2), even with a zero compiler exit status; a partial set is never reported as a complete build. Ordinary compiler failures retain their nonzero status. Output completeness is separate from provenance and byte correspondence.
