use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use schnorr::Transcript;

// represents the authentication data associated with a specific HTTP request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthContext {
    pub service_id: String,
    pub audience: String,
    pub method: String,
    pub path: String,
    pub body_sha256: String,
    pub nonce: String,
    pub timestamp_unix_secs: u64,
}

impl AuthContext {
    pub fn new(
        service_id: impl Into<String>,
        audience: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        body: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
        timestamp_unix_secs: u64,
    ) -> Self {
        let mut nonce = [0_u8; 16];
        rng.fill_bytes(&mut nonce);

        Self {
            service_id: service_id.into(),
            audience: audience.into(),
            method: method.into().to_uppercase(),
            path: path.into(),
            body_sha256: sha256_hex(body),
            nonce: hex::encode(nonce),
            timestamp_unix_secs,
        }
    }

    // Creates a Fiat–Shamir transcript that binds the Schnorr proof to a specific HTTP request.
    // All authentication context fields contribute to the challenge, so modifying any field invalidates the existing proof.
    pub(crate) fn transcript(&self) -> Transcript {
        let mut transcript = Transcript::new(b"zkp-auth-schnorr-http-v1");
 
        transcript.append_message(b"service_id", self.service_id.as_bytes());
        transcript.append_message(b"audience", self.audience.as_bytes());
        transcript.append_message(b"method", self.method.as_bytes());
        transcript.append_message(b"path", self.path.as_bytes());
        transcript.append_message(b"body_sha256", self.body_sha256.as_bytes());
        transcript.append_message(b"nonce", self.nonce.as_bytes());
        transcript.append_message(
            b"timestamp_unix_secs",
            self.timestamp_unix_secs.to_string().as_bytes(),
        );

        transcript
    }
}

pub(crate) fn sha256_hex(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}