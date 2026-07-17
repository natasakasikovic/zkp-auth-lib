use crate::group::{Commitment, PublicKey};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

#[derive(Clone, Debug, Default)]
pub struct Transcript {
    label: Vec<u8>,
    messages: Vec<Vec<u8>>,
}

impl Transcript {
    pub fn new(label: impl AsRef<[u8]>) -> Self {
        Self {
            label: label.as_ref().to_vec(),
            messages: Vec::new(),
        }
    }

    pub fn append_message(&mut self, label: impl AsRef<[u8]>, message: impl AsRef<[u8]>) {
        let label = label.as_ref();
        let message = message.as_ref();
        let mut encoded = Vec::with_capacity(label.len() + message.len() + 16);
        encoded.extend_from_slice(&(label.len() as u64).to_le_bytes());
        encoded.extend_from_slice(label);
        encoded.extend_from_slice(&(message.len() as u64).to_le_bytes());
        encoded.extend_from_slice(message);
        self.messages.push(encoded);
    }

    // derivation of the Fiat-Shamir challenge
    pub(crate) fn challenge_scalar(&self, public_key: &PublicKey, commitment: &Commitment) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(b"zkp-auth-schnorr-fiat-shamir-v1"); // domain separation
        hasher.update(&(self.label.len() as u64).to_le_bytes());
        hasher.update(&self.label);
        hasher.update(public_key.as_bytes()); // include public key Y
        hasher.update(commitment.as_bytes()); // include commitment R

        for message in &self.messages {
            hasher.update(message); // include additional context
        }

        let digest: [u8; 64] = hasher.finalize().into(); // compute hash
        Scalar::from_bytes_mod_order_wide(&digest) // convert hash to challenge scalar c
    }
}