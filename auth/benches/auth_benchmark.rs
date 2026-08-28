use criterion::{Criterion, black_box, criterion_group, criterion_main};

use rand_core::OsRng;

use auth::{
    AuthContext, ReplayProtector, ReplayProtectorConfig, SecretKey, create_auth_proof,
    current_unix_timestamp, verify_auth_proof,
};
fn bench_proof_generation(c: &mut Criterion) {
    let mut setup_rng = OsRng;
    let mut proof_rng = OsRng;

    let secret_key = SecretKey::random(&mut setup_rng);
    let timestamp = current_unix_timestamp();

    let mut group = c.benchmark_group("proof_generation");

    group.bench_function("create_auth_proof", |b| {
        b.iter_batched(
            || {
                AuthContext::new(
                    "order-service",
                    "warehouse-service",
                    "POST",
                    "/reserve",
                    br#"{"product_id":"laptop","quantity":1}"#,
                    &mut setup_rng,
                    timestamp,
                )
            },
            |context| black_box(create_auth_proof(&mut proof_rng, &secret_key, context)),
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_proof_verification(c: &mut Criterion) {
    let mut rng = OsRng;

    let secret_key = SecretKey::random(&mut rng);
    let public_key = secret_key.public_key();

    let timestamp = current_unix_timestamp();

    let mut group = c.benchmark_group("proof_verification");

    group.bench_function("verify_auth_proof", |b| {
        b.iter_batched(
            || {
                let context = AuthContext::new(
                    "order-service",
                    "warehouse-service",
                    "POST",
                    "/reserve",
                    br#"{"product_id":"laptop","quantity":1}"#,
                    &mut rng,
                    timestamp,
                );

                let bundle = create_auth_proof(&mut rng, &secret_key, context);

                let replay = ReplayProtector::new(ReplayProtectorConfig::default());

                (bundle, replay)
            },
            |(bundle, mut replay)| {
                black_box(
                    verify_auth_proof(
                        &bundle,
                        &public_key,
                        "warehouse-service",
                        "POST",
                        "/reserve",
                        br#"{"product_id":"laptop","quantity":1}"#,
                        timestamp,
                        &mut replay,
                    )
                    .expect("Proof verification should succeed"),
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(200)
        .warm_up_time(
            std::time::Duration::from_secs(2)
        );
    targets =
        bench_proof_generation,
        bench_proof_verification
}

criterion_main!(benches);
