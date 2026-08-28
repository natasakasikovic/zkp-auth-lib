use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

// representation of secret and public key
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretKey([u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey([u8; 32]);

impl SecretKey {
    // random generation of secret key
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(Scalar::random(rng).to_bytes())
    }

    // derivation of public key from secret key
    //  Y = x*G
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_point(&(self.scalar() * RISTRETTO_BASEPOINT_POINT))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Scalar::from_bytes_mod_order(bytes).to_bytes())
    }

    pub(crate) fn scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.0)
    }
}

impl PublicKey {
    pub(crate) fn from_point(point: &RistrettoPoint) -> Self {
        Self(point.compress().to_bytes())
    }

    pub(crate) fn point(&self) -> Option<RistrettoPoint> {
        CompressedRistretto(self.0).decompress()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment([u8; 32]);

impl Commitment {
    pub(crate) fn from_point(point: &RistrettoPoint) -> Self {
        Self(point.compress().to_bytes())
    }

    pub(crate) fn point(&self) -> Option<RistrettoPoint> {
        CompressedRistretto(self.0).decompress()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) fn generator() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}
