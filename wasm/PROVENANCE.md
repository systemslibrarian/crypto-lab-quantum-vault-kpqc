# Distributed WASM evidence

`provenance.json` records SHA-256 fingerprints of the tracked SMAUG-T and HAETAE artifacts used by the web demo. These match the adjacent tracked `.sha256` files. A matching fingerprint identifies bytes; it does not establish which upstream C source or compiler produced them.

The readable `wasm/src` wrappers and `wasm/build.sh` refer to source directories that are not tracked:

- `wasm/vendor/smaug-t/reference_implementation`
- `wasm/vendor/haetae/HAETAE-1.1.2/reference_implementation`

Exact upstream commits/archive digests and the original Emscripten environment are unknown. The version-like HAETAE directory name is not an authenticated source pin. Do not fill these fields from a current upstream release or claim that a successful web-demo test reproduces the cryptographic implementation.

`bash wasm/build.sh` now reports absent source prerequisites as UNREAD and exits 2 before compiling or creating output directories. This is an incomplete build, not a failed cryptographic test. Supplying directories alone does not establish their provenance. Before a reproducibility claim, record immutable upstream source identities, compiler/toolchain versions and flags, rebuild both artifacts, retain logs and compare bytes. Differences need investigation; they do not alone prove incorrect cryptography.

The build script's optimization flags and “constant-time hardened” wording are not evidence of a constant-time audit. This maintenance change does not modify binaries, wrappers or deployment configuration.
