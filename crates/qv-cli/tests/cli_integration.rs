// SPDX-License-Identifier: MIT
//! Integration tests for the `qv` CLI.
//!
//! These tests run the actual binary and verify end-to-end behavior:
//! keygen → encrypt → decrypt roundtrip.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Helper to get a Command for the `qv` binary.
fn qv() -> Command {
    Command::cargo_bin("qv").expect("qv binary should be built")
}

#[test]
fn cli_help_shows_usage() {
    qv().arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Quantum Vault"))
        .stdout(predicate::str::contains("threshold"));
}

#[test]
fn cli_version_shows_version() {
    qv().arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("qv"));
}

#[test]
fn keygen_creates_key_files() {
    let tmp = TempDir::new().unwrap();

    qv().args([
        "keygen",
        "--out-dir",
        tmp.path().to_str().unwrap(),
        "--name",
        "test-key",
        "--backend",
        "dev",
    ])
    .assert()
    .success();

    // Check that key files were created
    assert!(tmp.path().join("test-key.kem.pub").exists());
    assert!(tmp.path().join("test-key.kem.priv").exists());
    assert!(tmp.path().join("test-key.sig.pub").exists());
    assert!(tmp.path().join("test-key.sig.priv").exists());
}

#[test]
fn encrypt_decrypt_roundtrip_2_of_2() {
    let tmp = TempDir::new().unwrap();
    let plaintext = b"The treasure map is under the old oak tree";

    // Generate two KEM keypairs for 2-of-2 threshold
    for name in ["alice", "bob"] {
        qv().args([
            "keygen",
            "--out-dir",
            tmp.path().to_str().unwrap(),
            "--name",
            name,
            "--backend",
            "dev",
        ])
        .assert()
        .success();
    }

    // Write plaintext to a file
    let input_path = tmp.path().join("secret.txt");
    let output_path = tmp.path().join("secret.qvault");
    let recovered_path = tmp.path().join("recovered.txt");
    fs::write(&input_path, plaintext).unwrap();

    // Read public keys (base64-encoded)
    let alice_pub = fs::read_to_string(tmp.path().join("alice.kem.pub")).unwrap();
    let bob_pub = fs::read_to_string(tmp.path().join("bob.kem.pub")).unwrap();
    let pubkeys = format!("{},{}", alice_pub.trim(), bob_pub.trim());

    // Encrypt with 2-of-2 threshold
    qv().args([
        "encrypt",
        "--in",
        input_path.to_str().unwrap(),
        "--out",
        output_path.to_str().unwrap(),
        "--pubkeys",
        &pubkeys,
        "--threshold",
        "2",
        "--sign-key",
        tmp.path().join("alice.sig.priv").to_str().unwrap(),
        "--backend",
        "dev",
    ])
    .assert()
    .success();

    assert!(output_path.exists());

    // Read private keys for decryption
    let alice_priv = fs::read_to_string(tmp.path().join("alice.kem.priv")).unwrap();
    let bob_priv = fs::read_to_string(tmp.path().join("bob.kem.priv")).unwrap();
    let privkeys = format!("{},{}", alice_priv.trim(), bob_priv.trim());

    // Decrypt
    qv().args([
        "decrypt",
        "--in",
        output_path.to_str().unwrap(),
        "--out",
        recovered_path.to_str().unwrap(),
        "--privkeys",
        &privkeys,
        "--verify-key",
        tmp.path().join("alice.sig.pub").to_str().unwrap(),
        "--backend",
        "dev",
    ])
    .assert()
    .success();

    // Verify recovered plaintext matches original
    let recovered = fs::read(&recovered_path).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn encrypt_decrypt_roundtrip_2_of_3() {
    let tmp = TempDir::new().unwrap();
    let plaintext = b"Launch code: ALPHA-7749-ZULU";

    // Generate three KEM keypairs for 2-of-3 threshold
    for name in ["alice", "bob", "carol"] {
        qv().args([
            "keygen",
            "--out-dir",
            tmp.path().to_str().unwrap(),
            "--name",
            name,
            "--backend",
            "dev",
        ])
        .assert()
        .success();
    }

    // Write plaintext
    let input_path = tmp.path().join("secret.txt");
    let output_path = tmp.path().join("secret.qvault");
    let recovered_path = tmp.path().join("recovered.txt");
    fs::write(&input_path, plaintext).unwrap();

    // Read all three public keys
    let alice_pub = fs::read_to_string(tmp.path().join("alice.kem.pub")).unwrap();
    let bob_pub = fs::read_to_string(tmp.path().join("bob.kem.pub")).unwrap();
    let carol_pub = fs::read_to_string(tmp.path().join("carol.kem.pub")).unwrap();
    let pubkeys = format!(
        "{},{},{}",
        alice_pub.trim(),
        bob_pub.trim(),
        carol_pub.trim()
    );

    // Encrypt with 2-of-3 threshold
    qv().args([
        "encrypt",
        "--in",
        input_path.to_str().unwrap(),
        "--out",
        output_path.to_str().unwrap(),
        "--pubkeys",
        &pubkeys,
        "--threshold",
        "2",
        "--sign-key",
        tmp.path().join("alice.sig.priv").to_str().unwrap(),
        "--backend",
        "dev",
    ])
    .assert()
    .success();

    // Decrypt with only alice + bob (skipping carol) — should work with 2-of-3
    let alice_priv = fs::read_to_string(tmp.path().join("alice.kem.priv")).unwrap();
    let bob_priv = fs::read_to_string(tmp.path().join("bob.kem.priv")).unwrap();
    let privkeys = format!("{},{}", alice_priv.trim(), bob_priv.trim());

    qv().args([
        "decrypt",
        "--in",
        output_path.to_str().unwrap(),
        "--out",
        recovered_path.to_str().unwrap(),
        "--privkeys",
        &privkeys,
        "--verify-key",
        tmp.path().join("alice.sig.pub").to_str().unwrap(),
        "--backend",
        "dev",
    ])
    .assert()
    .success();

    let recovered = fs::read(&recovered_path).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn decrypt_fails_with_insufficient_keys() {
    let tmp = TempDir::new().unwrap();
    let plaintext = b"This should fail to decrypt with only one key";

    // Generate two keypairs for 2-of-2
    for name in ["alice", "bob"] {
        qv().args([
            "keygen",
            "--out-dir",
            tmp.path().to_str().unwrap(),
            "--name",
            name,
            "--backend",
            "dev",
        ])
        .assert()
        .success();
    }

    let input_path = tmp.path().join("secret.txt");
    let output_path = tmp.path().join("secret.qvault");
    let recovered_path = tmp.path().join("recovered.txt");
    fs::write(&input_path, plaintext).unwrap();

    let alice_pub = fs::read_to_string(tmp.path().join("alice.kem.pub")).unwrap();
    let bob_pub = fs::read_to_string(tmp.path().join("bob.kem.pub")).unwrap();
    let pubkeys = format!("{},{}", alice_pub.trim(), bob_pub.trim());

    // Encrypt with 2-of-2
    qv().args([
        "encrypt",
        "--in",
        input_path.to_str().unwrap(),
        "--out",
        output_path.to_str().unwrap(),
        "--pubkeys",
        &pubkeys,
        "--threshold",
        "2",
        "--sign-key",
        tmp.path().join("alice.sig.priv").to_str().unwrap(),
        "--backend",
        "dev",
    ])
    .assert()
    .success();

    // Try to decrypt with only alice's key (1-of-2) — should fail or produce garbage
    let alice_priv = fs::read_to_string(tmp.path().join("alice.kem.priv")).unwrap();

    let _result = qv()
        .args([
            "decrypt",
            "--in",
            output_path.to_str().unwrap(),
            "--out",
            recovered_path.to_str().unwrap(),
            "--privkeys",
            alice_priv.trim(),
            "--verify-key",
            tmp.path().join("alice.sig.pub").to_str().unwrap(),
            "--backend",
            "dev",
        ])
        .assert();

    // The CLI should either fail outright or produce incorrect output
    // (due to Shamir reconstruction with fewer than threshold shares)
    if recovered_path.exists() {
        let recovered = fs::read(&recovered_path).unwrap();
        assert_ne!(
            recovered, plaintext,
            "decryption with insufficient keys should not produce correct plaintext"
        );
    }
    // If the command failed, that's also acceptable
}

#[test]
fn encrypt_rejects_invalid_input_file() {
    let tmp = TempDir::new().unwrap();

    qv().args(["keygen", "--out-dir", tmp.path().to_str().unwrap()])
        .assert()
        .success();

    let pub_key = fs::read_to_string(tmp.path().join("qv-key.kem.pub")).unwrap();

    qv().args([
        "encrypt",
        "--in",
        "/nonexistent/file.txt",
        "--out",
        tmp.path().join("out.qvault").to_str().unwrap(),
        "--pubkeys",
        pub_key.trim(),
        "--threshold",
        "1",
        "--sign-key",
        tmp.path().join("qv-key.sig.priv").to_str().unwrap(),
    ])
    .assert()
    .failure();
}

#[test]
fn decrypt_rejects_invalid_container() {
    let tmp = TempDir::new().unwrap();

    // Create a garbage file that's not a valid qvault container
    let garbage_path = tmp.path().join("garbage.qvault");
    fs::write(&garbage_path, b"this is not a valid qvault container").unwrap();

    qv().args(["keygen", "--out-dir", tmp.path().to_str().unwrap()])
        .assert()
        .success();

    let priv_key = fs::read_to_string(tmp.path().join("qv-key.kem.priv")).unwrap();

    qv().args([
        "decrypt",
        "--in",
        garbage_path.to_str().unwrap(),
        "--out",
        tmp.path().join("out.txt").to_str().unwrap(),
        "--privkeys",
        priv_key.trim(),
        "--verify-key",
        tmp.path().join("qv-key.sig.pub").to_str().unwrap(),
    ])
    .assert()
    .failure();
}
