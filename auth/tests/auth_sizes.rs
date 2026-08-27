use auth::{
    create_auth_proof,
    current_unix_timestamp,
    AuthContext,
    SecretKey,
};

use rand_core::OsRng;

#[test]
#[ignore]
fn report_auth_sizes() {
    const ITERATIONS: usize = 1_000;

    let mut rng = OsRng;
    let secret_key = SecretKey::random(&mut rng);

    let mut json_proof_sizes = Vec::with_capacity(ITERATIONS);
    let mut json_bundle_sizes = Vec::with_capacity(ITERATIONS);
    let mut bincode_proof_sizes = Vec::with_capacity(ITERATIONS);
    let mut bincode_bundle_sizes = Vec::with_capacity(ITERATIONS);

    let mut raw_proof_size = 0usize;

    for i in 0..ITERATIONS {
        let context = AuthContext::new(
            "order-service",
            "warehouse-service",
            "POST",
            "/reserve",
            br#"{"product_id":"laptop","quantity":1}"#,
            &mut rng,
            current_unix_timestamp(),
        );

        let bundle = create_auth_proof(
            &mut rng,
            &secret_key,
            context,
        );

        // Raw Schnorr proof consists of a 32-byte commitment and a 32-byte response.
        if i == 0 {
            raw_proof_size =
                bundle.proof.commitment.as_bytes().len()
                + bundle.proof.response.len();
        }

        let json_proof =
            serde_json::to_vec(&bundle.proof)
                .expect("Proof JSON serialization should succeed");

        let json_bundle =
            serde_json::to_vec(&bundle)
                .expect("Bundle JSON serialization should succeed");

        let bincode_proof =
            bincode::serialize(&bundle.proof)
                .expect("Proof bincode serialization should succeed");

        let bincode_bundle =
            bincode::serialize(&bundle)
                .expect("Bundle bincode serialization should succeed");

        json_proof_sizes.push(json_proof.len());
        json_bundle_sizes.push(json_bundle.len());
        bincode_proof_sizes.push(bincode_proof.len());
        bincode_bundle_sizes.push(bincode_bundle.len());
    }

    let min_json_proof = *json_proof_sizes.iter().min().unwrap();
    let max_json_proof = *json_proof_sizes.iter().max().unwrap();
    let avg_json_proof =
        json_proof_sizes.iter().sum::<usize>() as f64 / ITERATIONS as f64;

    let min_json_bundle = *json_bundle_sizes.iter().min().unwrap();
    let max_json_bundle = *json_bundle_sizes.iter().max().unwrap();
    let avg_json_bundle =
        json_bundle_sizes.iter().sum::<usize>() as f64 / ITERATIONS as f64;

    let min_bincode_proof = *bincode_proof_sizes.iter().min().unwrap();
    let max_bincode_proof = *bincode_proof_sizes.iter().max().unwrap();
    let avg_bincode_proof =
        bincode_proof_sizes.iter().sum::<usize>() as f64 / ITERATIONS as f64;

    let min_bincode_bundle = *bincode_bundle_sizes.iter().min().unwrap();
    let max_bincode_bundle = *bincode_bundle_sizes.iter().max().unwrap();
    let avg_bincode_bundle =
        bincode_bundle_sizes.iter().sum::<usize>() as f64 / ITERATIONS as f64;

    println!();
    println!("=== Authentication size report ===");
    println!("Iterations: {ITERATIONS}");

    println!(
        "Raw SchnorrProof size: {} B",
        raw_proof_size
    );

    println!(
        "JSON SchnorrProof: min={} B, avg={:.2} B, max={} B",
        min_json_proof,
        avg_json_proof,
        max_json_proof
    );

    println!(
        "JSON AuthProofBundle: min={} B, avg={:.2} B, max={} B",
        min_json_bundle,
        avg_json_bundle,
        max_json_bundle
    );

    println!(
        "bincode SchnorrProof: min={} B, avg={:.2} B, max={} B",
        min_bincode_proof,
        avg_bincode_proof,
        max_bincode_proof
    );

    println!(
        "bincode AuthProofBundle: min={} B, avg={:.2} B, max={} B",
        min_bincode_bundle,
        avg_bincode_bundle,
        max_bincode_bundle
    );

    assert_eq!(
        raw_proof_size,
        64,
        "Raw Schnorr proof should consist of a 32-byte commitment \
         and a 32-byte response"
    );
}