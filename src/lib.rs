#![doc = include_str!("../README.md")]
//!
//! ---
//!
//! # API documentation
//!
//! Safe Rust bindings for Apple's `CryptoKit.framework` on macOS.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub mod ffi;
pub mod hashing;
pub mod hkdf;
pub mod hmac;
mod private;
pub mod public_key;
pub mod symmetric;

pub use error::{CryptoKitError, Result};
pub use hashing::{hash, md5, sha1, sha256, sha384, sha512, HashAlgorithm};
pub use hkdf::hkdf_sha256;
pub use hmac::{hmac, hmac_sha256, hmac_sha384, hmac_sha512, HmacAlgorithm};
pub use public_key::{
    KeyAgreementAlgorithm, KeyAgreementPrivateKey, KeyAgreementPublicKey, SharedSecret,
    SigningAlgorithm, SigningPrivateKey, SigningPublicKey,
};
pub use symmetric::{AesGcm, ChaCha20Poly1305, SymmetricKey, SymmetricKeySize};

/// Common imports for users of this crate.
pub mod prelude {
    pub use crate::error::{CryptoKitError, Result};
    pub use crate::hashing::{hash, md5, sha1, sha256, sha384, sha512, HashAlgorithm};
    pub use crate::hkdf::hkdf_sha256;
    pub use crate::hmac::{hmac, hmac_sha256, hmac_sha384, hmac_sha512, HmacAlgorithm};
    pub use crate::public_key::{
        KeyAgreementAlgorithm, KeyAgreementPrivateKey, KeyAgreementPublicKey, SharedSecret,
        SigningAlgorithm, SigningPrivateKey, SigningPublicKey,
    };
    pub use crate::symmetric::{AesGcm, ChaCha20Poly1305, SymmetricKey, SymmetricKeySize};
}
