//! Generic key-agreement helpers layered on the raw-curve modules.

use crate::ffi;

pub use crate::public_key::{
    KeyAgreementAlgorithm, KeyAgreementPrivateKey, KeyAgreementPublicKey, SharedSecret,
};
use crate::error::Result;

/// Trait mirroring `CryptoKit.DiffieHellmanKeyAgreement`.
pub trait DiffieHellmanKeyAgreement {
    /// Public-key type associated with this private key.
    type PublicKey;

    /// Export the matching public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    fn public_key(&self) -> Result<Self::PublicKey>;

    /// Derive a shared secret with a peer public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    fn shared_secret(&self, public_key: &Self::PublicKey) -> Result<SharedSecret>;
}

const P256_MASK: i32 = 1;
const P384_MASK: i32 = 1 << 1;
const P521_MASK: i32 = 1 << 2;
const X25519_MASK: i32 = 1 << 3;

/// Return the key-agreement algorithms supported by the Swift bridge.
#[must_use]
pub fn supported_algorithms() -> Vec<KeyAgreementAlgorithm> {
    let mask = unsafe { ffi::ck_key_agreement_supported_algorithm_mask() };
    let mut algorithms = Vec::new();
    if mask & P256_MASK != 0 {
        algorithms.push(KeyAgreementAlgorithm::P256);
    }
    if mask & P384_MASK != 0 {
        algorithms.push(KeyAgreementAlgorithm::P384);
    }
    if mask & P521_MASK != 0 {
        algorithms.push(KeyAgreementAlgorithm::P521);
    }
    if mask & X25519_MASK != 0 {
        algorithms.push(KeyAgreementAlgorithm::X25519);
    }
    algorithms
}
