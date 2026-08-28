mod context;
mod error;
mod proof;
mod replay;

pub use context::AuthContext;
pub use error::AuthVerificationError;

pub use proof::{AuthProofBundle, create_auth_proof, current_unix_timestamp, verify_auth_proof};

pub use replay::{ReplayProtector, ReplayProtectorConfig};

pub use schnorr::{PublicKey, SecretKey};
