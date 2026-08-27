use rand_core::OsRng;

use schnorr::{
    prove_non_interactive,
    verify_non_interactive,
    SecretKey,
    Transcript,
    VerificationError,
};

#[test]
fn valid_non_interactive_proof_verifies() {
    let mut rng = OsRng;
    let secret = SecretKey::random(&mut rng);
    let transcript = Transcript::new(b"service-auth-test");

    let (public_key, proof) =
        prove_non_interactive(&mut rng, &secret, &transcript);

    assert!(
        verify_non_interactive(&public_key, &proof, &transcript).is_ok()
    );
}

#[test]
fn proof_does_not_verify_for_different_public_key() {
    let mut rng = OsRng;
    let secret = SecretKey::random(&mut rng);
    let other_secret = SecretKey::random(&mut rng);
    let transcript = Transcript::new(b"service-auth-test");

    let (_, proof) =
        prove_non_interactive(&mut rng, &secret, &transcript);

    assert_eq!(
        verify_non_interactive(
            &other_secret.public_key(),
            &proof,
            &transcript,
        ),
        Err(VerificationError::InvalidProof)
    );
}

#[test]
fn proof_does_not_verify_for_different_transcript() {
    let mut rng = OsRng;
    let secret = SecretKey::random(&mut rng);

    let original_transcript =
        Transcript::new(b"service-auth-test");
    let different_transcript =
        Transcript::new(b"different-context");

    let (public_key, proof) =
        prove_non_interactive(
            &mut rng,
            &secret,
            &original_transcript,
        );

    assert_eq!(
        verify_non_interactive(
            &public_key,
            &proof,
            &different_transcript,
        ),
        Err(VerificationError::InvalidProof)
    );
}