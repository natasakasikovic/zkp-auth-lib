use auth::{
    AuthContext, AuthVerificationError, ReplayProtector, ReplayProtectorConfig, SecretKey,
    create_auth_proof, verify_auth_proof,
};

use rand_core::OsRng;

#[test]
fn auth_proof_is_bound_to_request_context() {
    let mut rng = OsRng;
    let secret = SecretKey::random(&mut rng);
    let public_key = secret.public_key();
    let timestamp = 1_800_000_000;

    let context = AuthContext::new(
        "order-service",
        "warehouse-service",
        "POST",
        "/reservations",
        br#"{"product_id":"laptop","quantity":1}"#,
        &mut rng,
        timestamp,
    );

    let proof = create_auth_proof(&mut rng, &secret, context.clone());
    let mut replay = ReplayProtector::new(ReplayProtectorConfig::default());

    assert!(
        verify_auth_proof(
            &proof,
            &public_key,
            "warehouse-service",
            "POST",
            "/reservations",
            br#"{"product_id":"laptop","quantity":1}"#,
            timestamp,
            &mut replay,
        )
        .is_ok()
    );

    let mut replay = ReplayProtector::new(ReplayProtectorConfig::default());

    assert_eq!(
        verify_auth_proof(
            &proof,
            &public_key,
            "warehouse-service",
            "POST",
            "/payments",
            br#"{"product_id":"laptop","quantity":1}"#,
            timestamp,
            &mut replay,
        ),
        Err(AuthVerificationError::RequestContextMismatch)
    );
}

#[test]
fn auth_proof_rejects_replayed_nonce() {
    let mut rng = OsRng;
    let secret = SecretKey::random(&mut rng);
    let public_key = secret.public_key();
    let timestamp = 1_800_000_000;

    let context = AuthContext::new(
        "order-service",
        "payment-service",
        "POST",
        "/payments",
        br#"{"amount":120000}"#,
        &mut rng,
        timestamp,
    );

    let proof = create_auth_proof(&mut rng, &secret, context);
    let mut replay = ReplayProtector::new(ReplayProtectorConfig::default());

    assert!(
        verify_auth_proof(
            &proof,
            &public_key,
            "payment-service",
            "POST",
            "/payments",
            br#"{"amount":120000}"#,
            timestamp,
            &mut replay,
        )
        .is_ok()
    );

    assert_eq!(
        verify_auth_proof(
            &proof,
            &public_key,
            "payment-service",
            "POST",
            "/payments",
            br#"{"amount":120000}"#,
            timestamp,
            &mut replay,
        ),
        Err(AuthVerificationError::ReplayDetected)
    );
}

#[test]
fn auth_proof_rejects_expired_timestamp() {
    let mut rng = OsRng;
    let secret = SecretKey::random(&mut rng);
    let public_key = secret.public_key();

    let context = AuthContext::new(
        "order-service",
        "warehouse-service",
        "POST",
        "/reservations",
        b"{}",
        &mut rng,
        1_800_000_000,
    );

    let proof = create_auth_proof(&mut rng, &secret, context);
    let mut replay = ReplayProtector::new(ReplayProtectorConfig::default());

    assert_eq!(
        verify_auth_proof(
            &proof,
            &public_key,
            "warehouse-service",
            "POST",
            "/reservations",
            b"{}",
            1_800_001_000,
            &mut replay,
        ),
        Err(AuthVerificationError::ExpiredTimestamp)
    );
}
