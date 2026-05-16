#![doc = include_str!("../README.md")]
//!
//! ---
//!
//! # API documentation
//!
//! Safe Rust bindings for Apple's `CryptoKit.framework` on macOS.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod aes_cbc;
pub mod aes_gcm;
pub mod chacha_poly;
pub mod curve25519;
pub mod error;
pub mod ffi;
pub mod hashing;
pub mod hkdf;
pub mod hmac;
pub mod insecure;
pub mod key_agreement;
pub mod key_derivation;
pub mod nist;
pub mod p256;
pub mod p384;
pub mod p521;
mod private;
pub mod public_key;
pub mod secure_enclave;
pub mod sha;
pub mod symmetric;
pub mod symmetric_key;

pub use aes_cbc::AesCbc;
pub use error::{CryptoKitError, Result};
pub use hashing::{hash, HashAlgorithm};
pub use hkdf::{hkdf, hkdf_sha256, hkdf_sha384, hkdf_sha512, HkdfAlgorithm};
pub use hmac::{hmac, hmac_sha256, hmac_sha384, hmac_sha512, HmacAlgorithm};
pub use insecure::{md5, sha1, InsecureHashAlgorithm};
pub use key_agreement::supported_algorithms as supported_key_agreement_algorithms;
pub use key_derivation::{
    derive as derive_shared_secret, derive_hkdf, derive_x963, KeyDerivationAlgorithm,
};
pub use nist::{supported_curves as supported_nist_curves, NistCurve};
pub use public_key::{
    KeyAgreementAlgorithm, KeyAgreementPrivateKey, KeyAgreementPublicKey, SharedSecret,
    SigningAlgorithm, SigningPrivateKey, SigningPublicKey,
};
pub use secure_enclave::{
    is_available as is_secure_enclave_available, SecureEnclaveKeyAgreementPrivateKey,
    SecureEnclaveSigningPrivateKey,
};
pub use sha::{digest as sha_digest, sha256, sha384, sha512, ShaAlgorithm};
pub use symmetric::{AesGcm, ChaCha20Poly1305, SymmetricKey, SymmetricKeySize};
pub use symmetric_key::supported_sizes as supported_symmetric_key_sizes;

/// Common imports for users of this crate.
pub mod prelude {
    pub use crate::aes_cbc::AesCbc;
    pub use crate::error::{CryptoKitError, Result};
    pub use crate::hashing::{hash, HashAlgorithm};
    pub use crate::hkdf::{hkdf, hkdf_sha256, hkdf_sha384, hkdf_sha512, HkdfAlgorithm};
    pub use crate::hmac::{hmac, hmac_sha256, hmac_sha384, hmac_sha512, HmacAlgorithm};
    pub use crate::insecure::{md5, sha1, InsecureHashAlgorithm};
    pub use crate::key_derivation::{derive_hkdf, derive_x963, KeyDerivationAlgorithm};
    pub use crate::nist::NistCurve;
    pub use crate::public_key::{
        KeyAgreementAlgorithm, KeyAgreementPrivateKey, KeyAgreementPublicKey, SharedSecret,
        SigningAlgorithm, SigningPrivateKey, SigningPublicKey,
    };
    pub use crate::secure_enclave::{
        is_available as is_secure_enclave_available, SecureEnclaveKeyAgreementPrivateKey,
        SecureEnclaveSigningPrivateKey,
    };
    pub use crate::sha::{digest as sha_digest, sha256, sha384, sha512, ShaAlgorithm};
    pub use crate::symmetric::{AesGcm, ChaCha20Poly1305, SymmetricKey, SymmetricKeySize};
}
