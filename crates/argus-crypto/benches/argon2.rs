#![allow(clippy::expect_used, clippy::panic)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const MIN_RATIO_OVER_WEAK: f64 = 4.0;

const WEAK_PHC: &str = "$argon2id$v=19$m=4096,t=1,p=1$\
                        AAAAAAAAAAAAAAAAAAAAAA$\
                        S2VlcCB0aGUgdGltaW5nIHRoZSBzYW1lIGZvcg";

fn median_millis(mut sample: impl FnMut()) -> f64 {
    let mut timings = Vec::with_capacity(9);
    for _ in 0..9 {
        let start = std::time::Instant::now();
        sample();
        timings.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    timings.sort_by(f64::total_cmp);
    timings.get(4).copied().unwrap_or_default()
}

fn argon2_verification(c: &mut Criterion) {
    let stored = argus_crypto::password::hash("a representative passphrase")
        .expect("the baseline hash must be produced");

    assert!(
        stored.contains(&format!(
            "m={},t={},p={}",
            argus_crypto::password::MEMORY_KIB,
            argus_crypto::password::TIME_COST,
            argus_crypto::password::PARALLELISM
        )),
        "the configured parameters are not the ones actually used: {stored}"
    );

    let configured = median_millis(|| {
        let _ = argus_crypto::password::verify("wrong", &stored);
    });
    let weak = median_millis(|| {
        let _ = argus_crypto::password::verify("wrong", WEAK_PHC);
    });

    let ratio = configured / weak.max(f64::EPSILON);

    println!(
        "argon2id: configured {configured:.2} ms, m=4096,t=1 baseline {weak:.2} ms, ratio {ratio:.1}x"
    );

    assert!(
        ratio >= MIN_RATIO_OVER_WEAK,
        "verification is only {ratio:.1}x the cost of a deliberately weak \
         m=4096,t=1 hash ({configured:.2} ms vs {weak:.2} ms). The parameters have \
         regressed. This ratio is used instead of a wall-clock threshold because the \
         same parameters take 235 ms unoptimised and 10 ms optimised on this machine, \
         so an absolute bound would encode the hardware rather than the setting."
    );

    c.bench_function("argon2id_verify", |b| {
        b.iter(|| {
            let _ = argus_crypto::password::verify(
                black_box("a representative passphrase"),
                black_box(&stored),
            );
        });
    });
}

criterion_group!(benches, argon2_verification);
criterion_main!(benches);
