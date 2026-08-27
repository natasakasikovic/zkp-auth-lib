pub mod fiat_shamir;
pub mod group;
pub mod prover;
pub mod verifier;

pub use fiat_shamir::Transcript;
pub use group::{Commitment, PublicKey, SecretKey};
pub use prover::{
    generate_interactive_commitment,
    prove_non_interactive,
    ProverState,
    SchnorrProof,
};
pub use verifier::{
    verify_interactive,
    verify_non_interactive,
    VerificationError,
};