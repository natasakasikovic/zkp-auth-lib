use crate::{
    fiat_shamir::Transcript,
    group::{generator, Commitment, PublicKey, SecretKey},
};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct ProverState {
    nonce: Scalar,
    commitment: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrProof {
    pub commitment: Commitment,
    pub response: [u8; 32],
}

// generation of an interactive commitment
pub fn generate_interactive_commitment(rng: &mut (impl RngCore + CryptoRng)) -> ProverState {
    let nonce = Scalar::random(rng); // r
    let commitment = Commitment::from_point(&(nonce * generator())); // R = r*G
    ProverState { nonce, commitment }
}

impl ProverState {
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    // generation of the Schnorr response and proof
    pub fn respond(self, secret_key: &SecretKey, challenge: Scalar) -> SchnorrProof {
        // compute the response: z = r + c * x
        let response = self.nonce + challenge * secret_key.scalar();
        SchnorrProof {
            commitment: self.commitment,
            response: response.to_bytes(),
        }
    }
}

// generation of a non-interactive Schnorr proof
pub fn prove_non_interactive(
    rng: &mut (impl RngCore + CryptoRng),
    secret_key: &SecretKey,
    transcript: &Transcript,
) -> (PublicKey, SchnorrProof) {
    let public_key = secret_key.public_key();
    let state = generate_interactive_commitment(rng);
    let challenge = transcript.challenge_scalar(&public_key, state.commitment());
    let proof = state.respond(secret_key, challenge);
    (public_key, proof)
}