pub mod fiat_shamir;
pub mod group;
pub mod prover;
pub mod verifier;

pub use fiat_shamir::Transcript;
pub use group::{Commitment, PublicKey, SecretKey};
pub use prover::{generate_interactive_commitment, prove_non_interactive, ProverState, SchnorrProof};
pub use verifier::{verify_interactive, verify_non_interactive, VerificationError};

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn valid_non_interactive_proof_verifies() {
        let mut rng = OsRng;
        let secret = SecretKey::random(&mut rng);
        let transcript = Transcript::new(b"service-auth-test");
        let (public_key, proof) = prove_non_interactive(&mut rng, &secret, &transcript);
        assert!(verify_non_interactive(&public_key, &proof, &transcript).is_ok());
    }

    #[test]
    fn proof_does_not_verify_for_different_public_key() {
        let mut rng = OsRng;
        let secret = SecretKey::random(&mut rng);
        let other_secret = SecretKey::random(&mut rng);
        let transcript = Transcript::new(b"service-auth-test");
        let (_, proof) = prove_non_interactive(&mut rng, &secret, &transcript);
        assert_eq!(
            verify_non_interactive(&other_secret.public_key(), &proof, &transcript),
            Err(VerificationError::InvalidProof)
        );
    }
}