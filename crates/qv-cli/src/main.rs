// SPDX-License-Identifier: MIT
//! Quantum Vault CLI — `qv`
//!
//! Commands:
//!   qv keygen   [--out-dir <dir>] [--backend dev|kpqc]
//!   qv encrypt  --in <file> --out <file> --pubkeys <k1,k2,...> --threshold <n> --sign-key <file> [--backend dev|kpqc]
//!   qv decrypt  --in <file> --out <file> --privkeys <index:path,...> --verify-key <file> [--backend dev|kpqc]

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, Subcommand};
#[cfg(feature = "dev-backend")]
use qv_core::crypto::backend::dev::{DevKem, DevSignature};
#[cfg(feature = "kpqc-native")]
use qv_core::crypto::backend::kpqc::{KpqcKem, KpqcSignature};
use qv_core::{
    container::QuantumVaultContainer,
    crypto::{kem::Kem, signature::Signature},
    decrypt_file, encrypt_file, DecryptOptions, EncryptOptions,
};
use std::{
    fs,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "qv",
    version,
    about = "Quantum Vault — threshold + post-quantum encrypted file vault",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a KEM keypair and a signature keypair.
    Keygen {
        /// Directory to write key files into (default: current directory).
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        /// Prefix for generated key file names.
        #[arg(long, default_value = "qv-key")]
        name: String,
        /// Cryptographic backend to use: `dev` (default, testing only) or
        /// `kpqc` (SMAUG-T + HAETAE, requires external source and kpqc-native).
        #[arg(long, default_value = "dev")]
        backend: String,
    },

    /// Encrypt a file into a .qvault container.
    Encrypt {
        /// Plaintext input file.
        #[arg(long, short)]
        r#in: PathBuf,
        /// Output .qvault container file.
        #[arg(long, short)]
        out: PathBuf,
        /// Comma-separated base64-encoded KEM public keys (one per share).
        #[arg(long)]
        pubkeys: String,
        /// Minimum number of shares required to decrypt.
        #[arg(long, default_value = "2")]
        threshold: u8,
        /// Path to base64-encoded signing private key file.
        #[arg(long)]
        sign_key: PathBuf,
        /// Cryptographic backend: `dev` or `kpqc`.
        #[arg(long, default_value = "dev")]
        backend: String,
    },

    /// Decrypt a .qvault container.
    Decrypt {
        /// Input .qvault container file.
        #[arg(long, short)]
        r#in: PathBuf,
        /// Output plaintext file.
        #[arg(long, short)]
        out: PathBuf,
        /// Comma-separated share-index:key-file pairs (for example, 1:alice.kem.priv,3:carol.kem.priv).
        /// Key bytes are read from files so they are not exposed in shell history or process arguments.
        #[arg(long)]
        privkeys: String,
        /// Path to base64-encoded signature public key file (for verification).
        #[arg(long)]
        verify_key: PathBuf,
        /// Cryptographic backend: `dev` or `kpqc`.
        #[arg(long, default_value = "dev")]
        backend: String,
    },
}

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

/// Build boxed KEM + Signature implementations from a backend name string.
///
/// Returns an error if the requested backend is unknown or unavailable in the
/// current feature configuration.
fn build_backends(backend: &str) -> Result<(Box<dyn Kem>, Box<dyn Signature>)> {
    match backend {
        "dev" => {
            #[cfg(not(feature = "dev-backend"))]
            return Err(anyhow!(
                "The `dev` backend is not available in this build.\n\
                 Compile with `--features dev-backend` for local testing only."
            ));
            #[cfg(feature = "dev-backend")]
            Ok((Box::new(DevKem), Box::new(DevSignature)))
        }
        "kpqc" => {
            #[cfg(not(feature = "kpqc-native"))]
            return Err(anyhow!(
                "The `kpqc` backend is not available in this build.\n\
                 Compile with `--features kpqc-native` after supplying the \
                 authenticated external C source. The `kpqc-wasm` core feature \
                 is an unimplemented scaffold, not a CLI backend."
            ));
            #[cfg(feature = "kpqc-native")]
            Ok((Box::new(KpqcKem), Box::new(KpqcSignature)))
        }
        other => Err(anyhow!(
            "Unknown backend {:?}. Valid options: `dev`, `kpqc`.",
            other
        )),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen {
            out_dir,
            name,
            backend,
        } => {
            let (kem, sig) = build_backends(&backend)?;
            cmd_keygen(kem.as_ref(), sig.as_ref(), &out_dir, &name)
        }
        Command::Encrypt {
            r#in,
            out,
            pubkeys,
            threshold,
            sign_key,
            backend,
        } => {
            let (kem, sig) = build_backends(&backend)?;
            cmd_encrypt(
                kem.as_ref(),
                sig.as_ref(),
                &r#in,
                &out,
                &pubkeys,
                threshold,
                &sign_key,
            )
        }
        Command::Decrypt {
            r#in,
            out,
            privkeys,
            verify_key,
            backend,
        } => {
            let (kem, sig) = build_backends(&backend)?;
            cmd_decrypt(
                kem.as_ref(),
                sig.as_ref(),
                &r#in,
                &out,
                &privkeys,
                &verify_key,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------------

fn cmd_keygen(kem: &dyn Kem, sig: &dyn Signature, out_dir: &Path, name: &str) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create output directory {}", out_dir.display()))?;

    // KEM keypair
    let (kem_pub, kem_priv) = kem.generate_keypair()?;
    let kem_priv = Zeroizing::new(kem_priv);
    let kem_pub_path = out_dir.join(format!("{name}.kem.pub"));
    let kem_priv_path = out_dir.join(format!("{name}.kem.priv"));
    write_b64(&kem_pub_path, &kem_pub)?;
    write_b64(&kem_priv_path, &kem_priv)?;
    eprintln!("KEM public key  → {}", kem_pub_path.display());
    eprintln!("KEM private key → {}", kem_priv_path.display());

    // Signature keypair
    let (sig_pub, sig_priv) = sig.generate_keypair()?;
    let sig_priv = Zeroizing::new(sig_priv);
    let sig_pub_path = out_dir.join(format!("{name}.sig.pub"));
    let sig_priv_path = out_dir.join(format!("{name}.sig.priv"));
    write_b64(&sig_pub_path, &sig_pub)?;
    write_b64(&sig_priv_path, &sig_priv)?;
    eprintln!("Sig public key  → {}", sig_pub_path.display());
    eprintln!("Sig private key → {}", sig_priv_path.display());

    println!("Backend: {} / {}", kem.algorithm_id(), sig.algorithm_id());
    Ok(())
}

// ---------------------------------------------------------------------------
// encrypt
// ---------------------------------------------------------------------------

fn cmd_encrypt(
    kem: &dyn Kem,
    sig: &dyn Signature,
    in_path: &Path,
    out_path: &Path,
    pubkeys_csv: &str,
    threshold: u8,
    sign_key_path: &Path,
) -> Result<()> {
    let plaintext = Zeroizing::new(
        fs::read(in_path)
            .with_context(|| format!("failed to read input file {}", in_path.display()))?,
    );

    let recipient_public_keys: Vec<Vec<u8>> = pubkeys_csv
        .split(',')
        .map(|s| {
            B64.decode(s.trim())
                .map_err(|e| anyhow!("invalid base64 pubkey: {e}"))
        })
        .collect::<Result<_>>()?;

    let share_count = recipient_public_keys.len() as u8;
    if threshold > share_count {
        return Err(anyhow!(
            "threshold ({threshold}) cannot exceed number of public keys ({share_count})"
        ));
    }

    let signer_private_key = read_b64(sign_key_path)
        .with_context(|| format!("failed to read signing key {}", sign_key_path.display()))?;

    let options = EncryptOptions {
        threshold,
        share_count,
        recipient_public_keys,
        signer_private_key,
    };

    let container = encrypt_file(&plaintext, &options, kem, sig)?;
    let bytes = container.to_bytes()?;

    fs::write(out_path, &bytes)
        .with_context(|| format!("failed to write container {}", out_path.display()))?;

    println!(
        "Encrypted {} bytes → {} ({} shares, threshold {})",
        plaintext.len(),
        out_path.display(),
        share_count,
        threshold,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// decrypt
// ---------------------------------------------------------------------------

fn cmd_decrypt(
    kem: &dyn Kem,
    sig: &dyn Signature,
    in_path: &Path,
    out_path: &Path,
    private_key_specs: &str,
    verify_key_path: &Path,
) -> Result<()> {
    let container_bytes = fs::read(in_path)
        .with_context(|| format!("failed to read container {}", in_path.display()))?;

    let container = QuantumVaultContainer::from_bytes(&container_bytes)
        .with_context(|| format!("failed to parse container {}", in_path.display()))?;

    let signer_public_key = read_b64(verify_key_path)
        .with_context(|| format!("failed to read verify key {}", verify_key_path.display()))?;
    let (recipient_private_keys, share_indices) = parse_private_key_specs(private_key_specs)?;

    let options = DecryptOptions {
        recipient_private_keys,
        share_indices,
        signer_public_key,
    };

    let plaintext = Zeroizing::new(decrypt_file(&container, &options, kem, sig)?);

    fs::write(out_path, &plaintext)
        .with_context(|| format!("failed to write plaintext {}", out_path.display()))?;

    println!(
        "Decrypted {} bytes → {}",
        plaintext.len(),
        out_path.display()
    );
    Ok(())
}

/// Read comma-separated `share-index:path` private-key specifications.
///
/// Keeping private key bytes in files avoids placing them in argv, where shell
/// history and same-host process inspection could disclose them. Any keys read
/// before a later specification error are cleared before returning.
fn parse_private_key_specs(specs: &str) -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut indices = Vec::new();

    for spec in specs.split(',') {
        let parsed = (|| -> Result<(u8, Vec<u8>)> {
            let (index, path) = spec.trim().split_once(':').ok_or_else(|| {
                anyhow!("invalid private-key specification {spec:?}; expected share-index:path")
            })?;
            let index = index
                .parse::<u8>()
                .map_err(|_| anyhow!("invalid share index {index:?}"))?;
            if index == 0 {
                return Err(anyhow!("share indices are one-based"));
            }
            if indices.contains(&index) {
                return Err(anyhow!("duplicate share index {index}"));
            }
            if path.is_empty() {
                return Err(anyhow!("private-key path for share {index} is empty"));
            }
            let key = read_b64(Path::new(path))
                .with_context(|| format!("failed to read private key for share {index}"))?;
            Ok((index, key))
        })();

        match parsed {
            Ok((index, key)) => {
                indices.push(index);
                keys.push(key);
            }
            Err(error) => {
                keys.zeroize();
                return Err(error);
            }
        }
    }

    if keys.is_empty() {
        return Err(anyhow!(
            "at least one private-key specification is required"
        ));
    }

    Ok((keys, indices))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write `bytes` as base64 (standard, padded) to `path` with owner-only
/// read/write permissions (0o600) to protect private key material (H-006).
fn write_b64(path: &Path, bytes: &[u8]) -> Result<()> {
    let encoded = Zeroizing::new(B64.encode(bytes));
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("failed to open {} for writing", path.display()))?;
        file.write_all(encoded.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))
    }
    #[cfg(not(unix))]
    {
        fs::write(path, encoded.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))
    }
}

/// Read base64 bytes from `path`.
fn read_b64(path: &Path) -> Result<Vec<u8>> {
    let s = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?,
    );
    B64.decode(s.trim())
        .map_err(|e| anyhow!("failed to decode base64 from {}: {e}", path.display()))
}
