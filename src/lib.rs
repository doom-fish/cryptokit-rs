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
pub mod hpke;
pub mod insecure;
pub mod key_agreement;
pub mod key_derivation;
pub mod kem;
pub mod key_wrap;
pub mod mldsa;
pub mod nist;
pub mod p256;
pub mod p384;
pub mod p521;
mod private;
pub mod public_key;
pub mod secure_enclave;
pub mod sha;
pub mod sha3;
pub mod symmetric;
pub mod symmetric_key;

pub use aes_cbc::AesCbc;
pub use error::{CryptoKitError, Result};
pub use hashing::{hash, HashAlgorithm};
pub use hkdf::{hkdf, hkdf_sha256, hkdf_sha384, hkdf_sha512, HkdfAlgorithm};
pub use hmac::{hmac, hmac_sha256, hmac_sha384, hmac_sha512, HmacAlgorithm};
pub use hpke::{
    Dhkem, HpkeAead, HpkeCiphersuite, HpkeDiffieHellmanPrivateKey,
    HpkeDiffieHellmanPrivateKeyGeneration, HpkeDiffieHellmanPublicKey, HpkeError, HpkeKem,
    HpkeKemPrivateKey, HpkeKemPrivateKeyGeneration, HpkeKemPublicKey, HpkeKdf,
    HpkePublicKeySerialization, Recipient as HpkeRecipient, Sender as HpkeSender,
};
pub use insecure::{md5, sha1, InsecureHashAlgorithm};
pub use key_agreement::{
    supported_algorithms as supported_key_agreement_algorithms, DiffieHellmanKeyAgreement,
};
pub use key_derivation::{
    derive as derive_shared_secret, derive_hkdf, derive_x963, KeyDerivationAlgorithm,
};
pub use kem::{EncapsulationResult, KemError, KemPrivateKey, KemPublicKey};
pub use key_wrap::AesKeyWrap;
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
pub use sha3::{
    hash as sha3_hash, sha3_256, sha3_384, sha3_512, Sha3Algorithm, Sha3_256, Sha3_256Digest,
    Sha3_384, Sha3_384Digest, Sha3_512, Sha3_512Digest,
};
pub use symmetric::{AesGcm, ChaCha20Poly1305, SymmetricKey, SymmetricKeySize};
pub use symmetric_key::supported_sizes as supported_symmetric_key_sizes;

/// Common imports for users of this crate.
pub mod prelude {
    pub use crate::aes_cbc::AesCbc;
    pub use crate::error::{CryptoKitError, Result};
    pub use crate::hashing::{hash, HashAlgorithm};
    pub use crate::hkdf::{hkdf, hkdf_sha256, hkdf_sha384, hkdf_sha512, HkdfAlgorithm};
    pub use crate::hmac::{hmac, hmac_sha256, hmac_sha384, hmac_sha512, HmacAlgorithm};
    pub use crate::hpke::{
        Dhkem, HpkeAead, HpkeCiphersuite, HpkeDiffieHellmanPrivateKey,
        HpkeDiffieHellmanPrivateKeyGeneration, HpkeDiffieHellmanPublicKey, HpkeKem,
        HpkeKemPrivateKey, HpkeKemPrivateKeyGeneration, HpkeKemPublicKey, HpkeKdf,
        HpkePublicKeySerialization, Recipient as HpkeRecipient, Sender as HpkeSender,
    };
    pub use crate::insecure::{md5, sha1, InsecureHashAlgorithm};
    pub use crate::key_derivation::{derive_hkdf, derive_x963, KeyDerivationAlgorithm};
    pub use crate::kem::{EncapsulationResult, KemPrivateKey, KemPublicKey};
    pub use crate::key_agreement::DiffieHellmanKeyAgreement;
    pub use crate::key_wrap::AesKeyWrap;
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
    pub use crate::sha3::{
        hash as sha3_hash, sha3_256, sha3_384, sha3_512, Sha3Algorithm, Sha3_256,
        Sha3_256Digest, Sha3_384, Sha3_384Digest, Sha3_512, Sha3_512Digest,
    };
    pub use crate::symmetric::{AesGcm, ChaCha20Poly1305, SymmetricKey, SymmetricKeySize};
}
