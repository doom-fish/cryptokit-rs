//! NIST prime-curve helpers.

use crate::error::Result;
use crate::ffi;
use crate::public_key::{
    KeyAgreementAlgorithm, KeyAgreementPrivateKey, SigningAlgorithm, SigningPrivateKey,
};

const P256_MASK: i32 = 1;
const P384_MASK: i32 = 1 << 1;
const P521_MASK: i32 = 1 << 2;

/// Supported NIST prime curves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NistCurve {
    P256,
    P384,
    P521,
}

impl NistCurve {
    /// Human-readable curve name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }

    /// Matching signing algorithm.
    #[must_use]
    pub const fn signing_algorithm(self) -> SigningAlgorithm {
        match self {
            Self::P256 => SigningAlgorithm::P256,
            Self::P384 => SigningAlgorithm::P384,
            Self::P521 => SigningAlgorithm::P521,
        }
    }

    /// Matching key-agreement algorithm.
    #[must_use]
    pub const fn key_agreement_algorithm(self) -> KeyAgreementAlgorithm {
        match self {
            Self::P256 => KeyAgreementAlgorithm::P256,
            Self::P384 => KeyAgreementAlgorithm::P384,
            Self::P521 => KeyAgreementAlgorithm::P521,
        }
    }
}

/// Return the NIST curves supported by the Swift bridge.
#[must_use]
pub fn supported_curves() -> Vec<NistCurve> {
    let mask = unsafe { ffi::ck_nist_supported_curve_mask() };
    let mut curves = Vec::new();
    if mask & P256_MASK != 0 {
        curves.push(NistCurve::P256);
    }
    if mask & P384_MASK != 0 {
        curves.push(NistCurve::P384);
    }
    if mask & P521_MASK != 0 {
        curves.push(NistCurve::P521);
    }
    curves
}

/// Generate a signing key for a NIST curve.
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_signing_private_key(curve: NistCurve) -> Result<SigningPrivateKey> {
    SigningPrivateKey::generate(curve.signing_algorithm())
}

/// Generate a key-agreement key for a NIST curve.
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_key_agreement_private_key(curve: NistCurve) -> Result<KeyAgreementPrivateKey> {
    KeyAgreementPrivateKey::generate(curve.key_agreement_algorithm())
}
