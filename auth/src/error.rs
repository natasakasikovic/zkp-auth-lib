use schnorr::VerificationError;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthVerificationError {
    #[error("proof was not created for the expected HTTP request")]
    RequestContextMismatch,
    #[error("proof timestamp is outside the accepted clock-skew window")]
    ExpiredTimestamp,
    #[error("nonce was already used")]
    ReplayDetected,
    #[error("public key in proof does not match expected service identity")]
    PublicKeyMismatch,
    #[error("invalid Schnorr proof: {0}")]
    InvalidProof(#[from] VerificationError),
}
