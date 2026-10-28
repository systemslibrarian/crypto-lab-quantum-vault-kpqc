//! build.rs for qv-core
//!
//! Under default conditions this script does nothing: the dev backend needs no
//! external libraries.
//!
//! When compiled with `--features kpqc-native` it tries to locate the SMAUG-T
//! and HAETAE reference C implementations and compile them into the crate using
//! the `cc` crate.  If the source directories are not found the build fails
//! with a human-readable error message rather than an obscure linker error.
//!
//! # Locating the source trees
//!
//! The build script checks:
//! 1. Environment variables `SMAUG_T_SRC` and `HAETAE_SRC` (absolute paths to
//!    parents containing exactly one extracted versioned source directory).
//! 2. `vendor/smaug-t/` and `vendor/haetae/` relative to the workspace root
//!    (`CARGO_MANIFEST_DIR/../..`).
//!
//! ## How to obtain the reference implementations
//!
//! Authenticate the source archives independently before use. The browser
//! reproduction manifest pins one reviewed public capture of each source tree;
//! the native build accepts extracted trees through the paths below.
//!
//! ```text
//! vendor/smaug-t/   ← extracted SMAUG-T reference implementation
//! vendor/haetae/    ← extracted HAETAE reference implementation
//! ```
//!
//! Then build with:
//! ```sh
//! cargo build -p qv-core --features kpqc-native
//! # or for the full workspace:
//! cargo build --features kpqc-native
//! ```
//!
//! # Fixed parameter set
//!
//! This FFI is fixed to SMAUG-T Level 3 and HAETAE Mode 3. The Rust buffer
//! sizes and exported symbol names are specific to those parameters, so this
//! build intentionally exposes no environment override for the security level.

fn main() {
    // Re-run this script if these env vars change.
    println!("cargo:rerun-if-env-changed=SMAUG_T_SRC");
    println!("cargo:rerun-if-env-changed=HAETAE_SRC");

    #[cfg(feature = "kpqc-native")]
    compile_kpqc_native();
}

/// Compile and link the SMAUG-T and HAETAE reference C implementations.
///
/// Only called when the `kpqc-native` feature is active.
#[cfg(feature = "kpqc-native")]
fn compile_kpqc_native() {
    use std::{env, path::PathBuf};

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // workspace root is two levels up from crates/qv-core
    let workspace_root = manifest_dir
        .join("../..")
        .canonicalize()
        .expect("could not resolve workspace root from CARGO_MANIFEST_DIR");

    // ── SMAUG-T ──────────────────────────────────────────────────────────────
    let smaug_src = env::var("SMAUG_T_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("vendor/smaug-t"));

    if !smaug_src.exists() {
        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  SMAUG-T source not found — kpqc-native build failed    ║");
        eprintln!("╠══════════════════════════════════════════════════════════╣");
        eprintln!("║  Expected:  {}  ║", smaug_src.display());
        eprintln!("║  Override:  export SMAUG_T_SRC=/path/to/SMAUG-T         ║");
        eprintln!("║  Source:    https://kpqc.or.kr/competition.html                         ║");
        eprintln!("║  Extract the SMAUG-T package and place it at vendor/smaug-t/               ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝");
        eprintln!();
        std::process::exit(1);
    }

    compile_smaug_t(&smaug_src);

    // ── HAETAE ───────────────────────────────────────────────────────────────
    let haetae_src = env::var("HAETAE_SRC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("vendor/haetae"));

    if !haetae_src.exists() {
        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  HAETAE source not found — kpqc-native build failed     ║");
        eprintln!("╠══════════════════════════════════════════════════════════╣");
        eprintln!("║  Expected:  {}   ║", haetae_src.display());
        eprintln!("║  Override:  export HAETAE_SRC=/path/to/HAETAE           ║");
        eprintln!("║  Source:    https://kpqc.or.kr/competition.html                        ║");
        eprintln!("║  Extract the HAETAE package and place it at vendor/haetae/               ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝");
        eprintln!();
        std::process::exit(1);
    }

    compile_haetae(&haetae_src);
}

/// Walk `base` one level deep to find the single extracted source directory
/// (e.g. `SMAUG-T-1.1.1/` or `HAETAE-1.1.2/`). Hidden directories like `.git/`
/// and any directory that does not contain `reference_implementation/` are
/// ignored so a vendored source tree can coexist with repository metadata.
/// The build fails with a helpful message if zero or more than one matching
/// sub-directory is found.
#[cfg(feature = "kpqc-native")]
fn find_versioned_subdir(base: &std::path::Path) -> std::path::PathBuf {
    let mut dirs: Vec<_> = std::fs::read_dir(base)
        .unwrap_or_else(|e| panic!("cannot read directory {}: {}", base.display(), e))
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .filter(|e| e.path().join("reference_implementation").is_dir())
        .collect();
    match dirs.len() {
        0 => panic!(
            "no sub-directories found under {}; expected a versioned directory like SMAUG-T-1.1.1/",
            base.display()
        ),
        1 => dirs.remove(0).path(),
        _ => panic!(
            "expected exactly one versioned sub-directory under {}, found {}; \
             set SMAUG_T_SRC / HAETAE_SRC to a parent containing exactly one \
             extracted directory with reference_implementation/",
            base.display(),
            dirs.len()
        ),
    }
}

/// Compile SMAUG-T reference C code using the `cc` crate.
///
/// # Source layout
///
/// ```text
/// vendor/smaug-t/
/// └── SMAUG-T-1.1.1/                   ← versioned subdir
///     └── reference_implementation/
///         ├── include/                 ← headers
///         └── src/                    ← .c files (randombytes.c excluded)
/// ```
///
/// `randombytes.c` is excluded and replaced by `randombytes_shim.c` in the
/// crate root, which sources OS entropy instead of the NIST KAT DRBG.
#[cfg(feature = "kpqc-native")]
fn compile_smaug_t(src: &std::path::Path) {
    let versioned = find_versioned_subdir(src);
    let ref_dir = versioned.join("reference_implementation");
    let src_dir = ref_dir.join("src");
    let inc_dir = ref_dir.join("include");

    if !src_dir.exists() {
        eprintln!(
            "build.rs: SMAUG-T src dir not found: {}\n\
             Expected layout: vendor/smaug-t/<version>/reference_implementation/src/",
            src_dir.display()
        );
        std::process::exit(1);
    }

    // Compile the reviewed library inputs explicitly. In particular, omit both
    // randombytes.c and rng.c: the former is replaced by our OS-entropy shim;
    // the latter is a KAT/seed-expander DRBG that depends on OpenSSL and also
    // defines a conflicting randombytes symbol.
    let c_files: Vec<_> = [
        "cbd.c",
        "ciphertext.c",
        "dg.c",
        "fips202.c",
        "hash.c",
        "hwt.c",
        "indcpa.c",
        "io.c",
        "kem.c",
        "key.c",
        "pack.c",
        "poly.c",
        "toomcook.c",
        "verify.c",
    ]
    .into_iter()
    .map(|name| src_dir.join(name))
    .collect();
    for file in &c_files {
        if !file.is_file() {
            panic!("required SMAUG-T source is missing: {}", file.display());
        }
    }

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let shim = manifest_dir.join("randombytes_shim.c");

    let mut build = cc::Build::new();
    build
        .include(&inc_dir)
        // The reviewed SMAUG-T source selects its parameter set with the
        // numeric SMAUG_MODE macro and namespaces this build as
        // cryptolab_smaug3_*. Keep this synchronized with kpqc_ffi.rs.
        .define("SMAUG_MODE", Some("3"))
        .flag_if_supported("-O2")
        .flag_if_supported("-std=c99")
        .flag_if_supported("-Wall");

    for f in &c_files {
        build.file(f);
        println!("cargo:rerun-if-changed={}", f.display());
    }
    build.file(&shim);
    println!("cargo:rerun-if-changed={}", shim.display());
    println!("cargo:rerun-if-changed={}", inc_dir.display());

    build.compile("smaug_t");
    println!("cargo:rustc-link-lib=static=smaug_t");
}

/// Compile HAETAE reference C code using the `cc` crate.
///
/// # Source layout
///
/// ```text
/// vendor/haetae/
/// └── HAETAE-1.1.2/                    ← versioned subdir
///     └── reference_implementation/
///         ├── include/                 ← headers (params.h, api.h, …)
///         └── src/                    ← .c files (randombytes.c excluded)
/// ```
///
/// The default mode in `config.h` is `HAETAE_MODE2`; we explicitly pass
/// `-DHAETAE_CONFIG_MODE=HAETAE_MODE3` to select Level 3.
///
/// `randombytes.c` is excluded and replaced by `randombytes_shim.c` in the
/// crate root, which sources OS entropy instead of the NIST KAT DRBG.
#[cfg(feature = "kpqc-native")]
fn compile_haetae(src: &std::path::Path) {
    use std::ffi::OsStr;

    let versioned = find_versioned_subdir(src);
    let ref_dir = versioned.join("reference_implementation");
    let src_dir = ref_dir.join("src");
    let inc_dir = ref_dir.join("include");

    if !src_dir.exists() {
        eprintln!(
            "build.rs: HAETAE src dir not found: {}\n\
             Expected layout: vendor/haetae/<version>/reference_implementation/src/",
            src_dir.display()
        );
        std::process::exit(1);
    }

    // Collect .c files, excluding randombytes.c (replaced by our OS-entropy shim).
    let c_files: Vec<_> = std::fs::read_dir(&src_dir)
        .expect("could not read HAETAE src dir")
        .flatten()
        .filter(|e| {
            let p = e.path();
            p.extension().is_some_and(|ext| ext == "c")
                && p.file_name() != Some(OsStr::new("randombytes.c"))
        })
        .map(|e| e.path())
        .collect();

    if c_files.is_empty() {
        eprintln!(
            "build.rs: no .c files found in {} — check HAETAE source layout",
            src_dir.display()
        );
        std::process::exit(1);
    }

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let shim = manifest_dir.join("randombytes_shim.c");

    let mut build = cc::Build::new();
    build
        .include(&inc_dir)
        // config.h defaults to HAETAE_MODE2; override to HAETAE_MODE3 (enum value 1).
        .define("HAETAE_CONFIG_MODE", Some("HAETAE_MODE3"))
        .flag_if_supported("-O2")
        .flag_if_supported("-std=c99")
        .flag_if_supported("-Wall");

    for f in &c_files {
        build.file(f);
        println!("cargo:rerun-if-changed={}", f.display());
    }
    build.file(&shim);
    println!("cargo:rerun-if-changed={}", shim.display());
    println!("cargo:rerun-if-changed={}", inc_dir.display());

    build.compile("haetae");
    println!("cargo:rustc-link-lib=static=haetae");
}
