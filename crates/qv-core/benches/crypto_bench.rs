/// Criterion benchmarks for the Quantum Vault core cryptographic primitives.
///
/// Run with:
/// ```sh
/// cargo bench -p qv-core
/// ```
/// or, for a quick smoke check without HTML reports:
/// ```sh
/// cargo bench -p qv-core -- --output-format bencher 2>&1 | grep "^test"
/// ```
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use qv_core::{
    decrypt_with_threshold, encrypt_bytes, encrypt_with_threshold,
    reconstruct_secret, split_secret, KeyShare,
};

// ── AES-256-GCM via the high-level API ───────────────────────────────────────

fn bench_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline");

    for size in [64_usize, 1_024, 64 * 1_024] {
        let plain: Vec<u8> = (0u8..).take(size).collect();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt_2of2", size), &plain, |b, p| {
            b.iter(|| {
                let _ = encrypt_bytes(black_box(p)).unwrap();
            });
        });

        group.bench_with_input(BenchmarkId::new("roundtrip_2of2", size), &plain, |b, p| {
            // Pre-encrypt once outside the loop to measure decrypt separately.
            let (ct, keys, sig_pub) = encrypt_bytes(p).unwrap();
            b.iter(|| {
                let _ = decrypt_with_threshold(
                    black_box(&ct),
                    black_box(&keys),
                    black_box(&sig_pub),
                )
                .unwrap();
            });
        });
    }

    group.finish();
}

// ── Shamir split / reconstruct ────────────────────────────────────────────────

fn bench_shamir(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir");

    let secret_32 = vec![0x42u8; 32];
    let secret_64 = vec![0x42u8; 64];

    group.bench_function("split_2of2_32b", |b| {
        b.iter(|| {
            let _ = split_secret(black_box(&secret_32), 2, 2).unwrap();
        });
    });

    group.bench_function("split_3of5_32b", |b| {
        b.iter(|| {
            let _ = split_secret(black_box(&secret_32), 5, 3).unwrap();
        });
    });

    group.bench_function("split_5of7_64b", |b| {
        b.iter(|| {
            let _ = split_secret(black_box(&secret_64), 7, 5).unwrap();
        });
    });

    // Reconstruction: pre-generate shares outside the timed loop.
    let shares_2of2 = split_secret(&secret_32, 2, 2).unwrap();
    group.bench_function("reconstruct_2of2_32b", |b| {
        b.iter(|| {
            let _ = reconstruct_secret(black_box(&shares_2of2)).unwrap();
        });
    });

    let shares_3of5 = split_secret(&secret_32, 5, 3).unwrap();
    let min_shares_3of5: Vec<KeyShare> = shares_3of5.into_iter().take(3).collect();
    group.bench_function("reconstruct_3of5_32b", |b| {
        b.iter(|| {
            let _ = reconstruct_secret(black_box(&min_shares_3of5)).unwrap();
        });
    });

    group.finish();
}

// ── threshold encrypt with different N/T ─────────────────────────────────────

fn bench_threshold_shapes(c: &mut Criterion) {
    let plain = b"benchmark threshold shapes";
    let mut group = c.benchmark_group("threshold_encrypt");

    for (n, t) in [(2u8, 2u8), (3, 2), (5, 3), (7, 5)] {
        group.bench_with_input(
            BenchmarkId::new(format!("{n}of{t}"), ""),
            &(n, t),
            |b, &(n, t)| {
                b.iter(|| {
                    let _ = encrypt_with_threshold(black_box(plain), n, t).unwrap();
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_encrypt_decrypt, bench_shamir, bench_threshold_shapes);
criterion_main!(benches);
