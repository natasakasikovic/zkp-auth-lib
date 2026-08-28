use crate::{
    fiat_shamir::Transcript,
    group::{Commitment, PublicKey, generator},
    prover::SchnorrProof,
};
use curve25519_dalek::scalar::Scalar;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerificationError {
    #[error("public key is not a valid Ristretto point")]
    InvalidPublicKey,
    #[error("commitment is not a valid Ristretto point")]
    InvalidCommitment,
    #[error("proof response is not a canonical scalar")]
    InvalidResponse,
    #[error("Schnorr equation does not hold")]
    InvalidProof,
}

pub fn verify_interactive(
    public_key: &PublicKey,
    commitment: &Commitment,
    challenge: Scalar,
    response: [u8; 32],
) -> Result<(), VerificationError> {
    let public_key_point = public_key
        .point()
        .ok_or(VerificationError::InvalidPublicKey)?;
    let commitment_point = commitment
        .point()
        .ok_or(VerificationError::InvalidCommitment)?;
    let response_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(response))
        .ok_or(VerificationError::InvalidResponse)?;

    let left = response_scalar * generator();
    let right = commitment_point + challenge * public_key_point;

    if left == right {
        Ok(())
    } else {
        Err(VerificationError::InvalidProof)
    }
}

pub fn verify_non_interactive(
    public_key: &PublicKey,
    proof: &SchnorrProof,
    transcript: &Transcript,
) -> Result<(), VerificationError> {
    let challenge = transcript.challenge_scalar(public_key, &proof.commitment);
    verify_interactive(public_key, &proof.commitment, challenge, proof.response)
}
