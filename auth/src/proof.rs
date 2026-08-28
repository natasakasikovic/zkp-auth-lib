use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{CryptoRng, RngCore};
use schnorr::{PublicKey, SchnorrProof, SecretKey, prove_non_interactive, verify_non_interactive};
use serde::{Deserialize, Serialize};

use crate::{
    context::{AuthContext, sha256_hex},
    error::AuthVerificationError,
    replay::ReplayProtector,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProofBundle {
    pub public_key: PublicKey,
    pub context: AuthContext,
    pub proof: SchnorrProof,
}

pub fn create_auth_proof(
    rng: &mut (impl RngCore + CryptoRng),
    secret_key: &SecretKey,
    context: AuthContext,
) -> AuthProofBundle {
    let transcript = context.transcript();
    let (public_key, proof) = prove_non_interactive(rng, secret_key, &transcript);

    AuthProofBundle {
        public_key,
        context,
        proof,
    }
}

pub fn verify_auth_proof(
    bundle: &AuthProofBundle,
    expected_public_key: &PublicKey,
    expected_audience: &str,
    method: &str,
    path: &str,
    body: &[u8],
    now_unix_secs: u64,
    replay_protector: &mut ReplayProtector,
) -> Result<(), AuthVerificationError> {
    if &bundle.public_key != expected_public_key {
        return Err(AuthVerificationError::PublicKeyMismatch);
    }

    if bundle.context.audience != expected_audience
        || bundle.context.method != method.to_uppercase()
        || bundle.context.path != path
        || bundle.context.body_sha256 != sha256_hex(body)
    {
        return Err(AuthVerificationError::RequestContextMismatch);
    }

    replay_protector.verify_and_store(&bundle.context, now_unix_secs)?;

    let transcript = bundle.context.transcript();
    verify_non_interactive(&bundle.public_key, &bundle.proof, &transcript)?;

    Ok(())
}

pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
