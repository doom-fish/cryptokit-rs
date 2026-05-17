//! Hybrid Public Key Encryption helpers.

use core::ffi::{c_char, c_void};
use std::ptr;
use std::ptr::NonNull;

use crate::curve25519::{X25519PrivateKey, X25519PublicKey};
use crate::error::{from_swift, Result};
use crate::ffi;
use crate::kem::{
    KemPrivateKey, KemPublicKey, XWingMlkem768X25519PrivateKey, XWingMlkem768X25519PublicKey,
};
use crate::key_agreement::DiffieHellmanKeyAgreement;
use crate::p256::{P256KeyAgreementPrivateKey, P256KeyAgreementPublicKey};
use crate::p384::{P384KeyAgreementPrivateKey, P384KeyAgreementPublicKey};
use crate::p521::{P521KeyAgreementPrivateKey, P521KeyAgreementPublicKey};
use crate::private::bridge_bytes;
use crate::symmetric::SymmetricKey;

/// HPKE key-derivation functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HpkeKdf {
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
}

impl HpkeKdf {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::HkdfSha256 => ffi::hpke_kdf::HKDF_SHA256,
            Self::HkdfSha384 => ffi::hpke_kdf::HKDF_SHA384,
            Self::HkdfSha512 => ffi::hpke_kdf::HKDF_SHA512,
        }
    }
}

/// HPKE AEAD algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HpkeAead {
    AesGcm128,
    AesGcm256,
    ChaChaPoly,
    ExportOnly,
}

impl HpkeAead {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::AesGcm128 => ffi::hpke_aead::AES_GCM_128,
            Self::AesGcm256 => ffi::hpke_aead::AES_GCM_256,
            Self::ChaChaPoly => ffi::hpke_aead::CHACHA_POLY,
            Self::ExportOnly => ffi::hpke_aead::EXPORT_ONLY,
        }
    }
}

/// HPKE KEM choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HpkeKem {
    P256HkdfSha256,
    P384HkdfSha384,
    P521HkdfSha512,
    Curve25519HkdfSha256,
    XWingMlkem768X25519,
}

impl HpkeKem {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::P256HkdfSha256 => ffi::hpke_kem::P256_HKDF_SHA256,
            Self::P384HkdfSha384 => ffi::hpke_kem::P384_HKDF_SHA384,
            Self::P521HkdfSha512 => ffi::hpke_kem::P521_HKDF_SHA512,
            Self::Curve25519HkdfSha256 => ffi::hpke_kem::CURVE25519_HKDF_SHA256,
            Self::XWingMlkem768X25519 => ffi::hpke_kem::XWING_MLKEM768_X25519,
        }
    }
}

/// An HPKE ciphersuite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HpkeCiphersuite {
    kem: HpkeKem,
    kdf: HpkeKdf,
    aead: HpkeAead,
}

impl HpkeCiphersuite {
    /// P-256 / HKDF-SHA256 / AES-GCM-256.
    pub const P256_SHA256_AES_GCM_256: Self = Self::new(
        HpkeKem::P256HkdfSha256,
        HpkeKdf::HkdfSha256,
        HpkeAead::AesGcm256,
    );
    /// P-384 / HKDF-SHA384 / AES-GCM-256.
    pub const P384_SHA384_AES_GCM_256: Self = Self::new(
        HpkeKem::P384HkdfSha384,
        HpkeKdf::HkdfSha384,
        HpkeAead::AesGcm256,
    );
    /// P-521 / HKDF-SHA512 / AES-GCM-256.
    pub const P521_SHA512_AES_GCM_256: Self = Self::new(
        HpkeKem::P521HkdfSha512,
        HpkeKdf::HkdfSha512,
        HpkeAead::AesGcm256,
    );
    /// X25519 / HKDF-SHA256 / ChaCha20-Poly1305.
    pub const CURVE25519_SHA256_CHACHA_POLY: Self = Self::new(
        HpkeKem::Curve25519HkdfSha256,
        HpkeKdf::HkdfSha256,
        HpkeAead::ChaChaPoly,
    );
    /// X-Wing / HKDF-SHA256 / AES-GCM-256.
    pub const XWING_MLKEM768_X25519_SHA256_AES_GCM_256: Self = Self::new(
        HpkeKem::XWingMlkem768X25519,
        HpkeKdf::HkdfSha256,
        HpkeAead::AesGcm256,
    );

    /// Build a ciphersuite from its component algorithms.
    #[must_use]
    pub const fn new(kem: HpkeKem, kdf: HpkeKdf, aead: HpkeAead) -> Self {
        Self { kem, kdf, aead }
    }

    /// KEM component.
    #[must_use]
    pub const fn kem(self) -> HpkeKem {
        self.kem
    }

    /// KDF component.
    #[must_use]
    pub const fn kdf(self) -> HpkeKdf {
        self.kdf
    }

    /// AEAD component.
    #[must_use]
    pub const fn aead(self) -> HpkeAead {
        self.aead
    }
}

/// Cases currently defined by `CryptoKit.HPKE.Errors`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HpkeError {
    InconsistentParameters,
    InconsistentCiphersuiteAndKey,
    ExportOnlyMode,
    InconsistentPskInputs,
    ExpectedPsk,
    UnexpectedPsk,
    OutOfRangeSequenceNumber,
    CiphertextTooShort,
}

/// Marker mirroring the `CryptoKit.HPKE.DHKEM` namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Dhkem;

/// Trait mirroring `CryptoKit.HPKEPublicKeySerialization`.
pub trait HpkePublicKeySerialization: Sized {
    /// Construct a key from its HPKE serialization.
    ///
    /// # Errors
    ///
    /// Returns an error if the serialization is invalid for the selected KEM.
    fn from_hpke_serialization(serialization: &[u8], kem: HpkeKem) -> Result<Self>;

    /// Export the key's HPKE serialization for the selected KEM.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected KEM is incompatible with the key type.
    fn hpke_representation(&self, kem: HpkeKem) -> Result<Vec<u8>>;
}

/// Trait mirroring `CryptoKit.HPKEDiffieHellmanPublicKey`.
pub trait HpkeDiffieHellmanPublicKey: HpkePublicKeySerialization {}

/// Trait mirroring `CryptoKit.HPKEDiffieHellmanPrivateKey`.
pub trait HpkeDiffieHellmanPrivateKey: DiffieHellmanKeyAgreement
where
    Self::PublicKey: HpkeDiffieHellmanPublicKey,
{
}

/// Trait mirroring `CryptoKit.HPKEDiffieHellmanPrivateKeyGeneration`.
pub trait HpkeDiffieHellmanPrivateKeyGeneration: HpkeDiffieHellmanPrivateKey
where
    Self::PublicKey: HpkeDiffieHellmanPublicKey,
{
    /// Generate a fresh private key.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    fn generate() -> Result<Self>
    where
        Self: Sized;
}

/// Trait mirroring `CryptoKit.HPKEKEMPublicKey`.
pub trait HpkeKemPublicKey: HpkePublicKeySerialization + KemPublicKey {}

/// Trait mirroring `CryptoKit.HPKEKEMPrivateKey`.
pub trait HpkeKemPrivateKey: KemPrivateKey
where
    Self::PublicKey: HpkeKemPublicKey,
{
}

/// Trait mirroring `CryptoKit.HPKEKEMPrivateKeyGeneration`.
pub trait HpkeKemPrivateKeyGeneration: HpkeKemPrivateKey
where
    Self::PublicKey: HpkeKemPublicKey,
{
    /// Generate a fresh private key.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    fn generate() -> Result<Self>
    where
        Self: Sized;
}

#[doc(hidden)]
pub trait HpkeDiffieHellmanPublicKeyImpl: HpkeDiffieHellmanPublicKey {
    fn hpke_dh_algorithm_ffi(&self) -> i32;
    fn hpke_raw_public_key(&self) -> &[u8];
}

#[doc(hidden)]
pub trait HpkeDiffieHellmanPrivateKeyImpl: HpkeDiffieHellmanPrivateKey
where
    Self::PublicKey: HpkeDiffieHellmanPublicKey,
{
    fn hpke_dh_algorithm_ffi(&self) -> i32;
    fn hpke_private_key_bytes(&self) -> Result<Vec<u8>>;
}

#[doc(hidden)]
pub trait HpkeKemPublicKeyImpl: HpkeKemPublicKey {
    fn hpke_kem_algorithm_ffi(&self) -> i32;
    fn hpke_raw_public_key(&self) -> &[u8];
}

#[doc(hidden)]
pub trait HpkeKemPrivateKeyImpl: HpkeKemPrivateKey
where
    Self::PublicKey: HpkeKemPublicKey,
{
    fn hpke_kem_algorithm_ffi(&self) -> i32;
    fn hpke_private_key_bytes(&self) -> Result<Vec<u8>>;
}

/// Stateful HPKE sender context.
#[derive(Debug)]
pub struct Sender {
    handle: NonNull<c_void>,
}

impl Sender {
    /// Create a sender for Diffie-Hellman recipient keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected ciphersuite is incompatible with the recipient key.
    pub fn new<P>(recipient_key: &P, ciphersuite: HpkeCiphersuite, info: &[u8]) -> Result<Self>
    where
        P: HpkeDiffieHellmanPublicKeyImpl,
    {
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_hpke_sender_create_dh(
                recipient_key.hpke_dh_algorithm_ffi(),
                recipient_key.hpke_raw_public_key().as_ptr(),
                recipient_key.hpke_raw_public_key().len(),
                ciphersuite.kem.as_ffi(),
                ciphersuite.kdf.as_ffi(),
                ciphersuite.aead.as_ffi(),
                info.as_ptr(),
                info.len(),
                ffi::hpke_mode::BASE,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                &mut error,
            )
        };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Create a sender with a pre-shared key for Diffie-Hellman recipient keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected ciphersuite is incompatible with the recipient key.
    pub fn new_with_psk<P>(
        recipient_key: &P,
        ciphersuite: HpkeCiphersuite,
        info: &[u8],
        preshared_key: &SymmetricKey,
        preshared_key_identifier: &[u8],
    ) -> Result<Self>
    where
        P: HpkeDiffieHellmanPublicKeyImpl,
    {
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_hpke_sender_create_dh(
                recipient_key.hpke_dh_algorithm_ffi(),
                recipient_key.hpke_raw_public_key().as_ptr(),
                recipient_key.hpke_raw_public_key().len(),
                ciphersuite.kem.as_ffi(),
                ciphersuite.kdf.as_ffi(),
                ciphersuite.aead.as_ffi(),
                info.as_ptr(),
                info.len(),
                ffi::hpke_mode::PSK,
                ptr::null(),
                0,
                preshared_key.as_bytes().as_ptr(),
                preshared_key.as_bytes().len(),
                preshared_key_identifier.as_ptr(),
                preshared_key_identifier.len(),
                &mut error,
            )
        };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Create an authenticated sender for Diffie-Hellman recipient keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected ciphersuite is incompatible with the key types.
    pub fn new_authenticated<K>(
        recipient_key: &K::PublicKey,
        ciphersuite: HpkeCiphersuite,
        info: &[u8],
        authentication_key: &K,
    ) -> Result<Self>
    where
        K: HpkeDiffieHellmanPrivateKeyImpl,
        K::PublicKey: HpkeDiffieHellmanPublicKeyImpl,
    {
        let auth_key_bytes = authentication_key.hpke_private_key_bytes()?;
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_hpke_sender_create_dh(
                recipient_key.hpke_dh_algorithm_ffi(),
                recipient_key.hpke_raw_public_key().as_ptr(),
                recipient_key.hpke_raw_public_key().len(),
                ciphersuite.kem.as_ffi(),
                ciphersuite.kdf.as_ffi(),
                ciphersuite.aead.as_ffi(),
                info.as_ptr(),
                info.len(),
                ffi::hpke_mode::AUTH,
                auth_key_bytes.as_ptr(),
                auth_key_bytes.len(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                &mut error,
            )
        };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Create an authenticated sender with a pre-shared key for Diffie-Hellman recipient keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected ciphersuite is incompatible with the key types.
    pub fn new_authenticated_with_psk<K>(
        recipient_key: &K::PublicKey,
        ciphersuite: HpkeCiphersuite,
        info: &[u8],
        authentication_key: &K,
        preshared_key: &SymmetricKey,
        preshared_key_identifier: &[u8],
    ) -> Result<Self>
    where
        K: HpkeDiffieHellmanPrivateKeyImpl,
        K::PublicKey: HpkeDiffieHellmanPublicKeyImpl,
    {
        let auth_key_bytes = authentication_key.hpke_private_key_bytes()?;
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_hpke_sender_create_dh(
                recipient_key.hpke_dh_algorithm_ffi(),
                recipient_key.hpke_raw_public_key().as_ptr(),
                recipient_key.hpke_raw_public_key().len(),
                ciphersuite.kem.as_ffi(),
                ciphersuite.kdf.as_ffi(),
                ciphersuite.aead.as_ffi(),
                info.as_ptr(),
                info.len(),
                ffi::hpke_mode::AUTH_PSK,
                auth_key_bytes.as_ptr(),
                auth_key_bytes.len(),
                preshared_key.as_bytes().as_ptr(),
                preshared_key.as_bytes().len(),
                preshared_key_identifier.as_ptr(),
                preshared_key_identifier.len(),
                &mut error,
            )
        };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Create a sender for KEM recipient keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected ciphersuite is incompatible with the recipient key.
    pub fn new_with_kem<P>(
        recipient_key: &P,
        ciphersuite: HpkeCiphersuite,
        info: &[u8],
    ) -> Result<Self>
    where
        P: HpkeKemPublicKeyImpl,
    {
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_hpke_sender_create_kem(
                recipient_key.hpke_kem_algorithm_ffi(),
                recipient_key.hpke_raw_public_key().as_ptr(),
                recipient_key.hpke_raw_public_key().len(),
                ciphersuite.kem.as_ffi(),
                ciphersuite.kdf.as_ffi(),
                ciphersuite.aead.as_ffi(),
                info.as_ptr(),
                info.len(),
                &mut error,
            )
        };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Export the sender's encapsulated key.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn encapsulated_key(&self) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_hpke_sender_encapsulated_key(self.handle.as_ptr(), out, out_len, error_out)
        })
    }

    /// Seal a plaintext without additional authenticated data.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn seal(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.seal_with_aad(message, &[])
    }

    /// Seal a plaintext with additional authenticated data.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn seal_with_aad(&mut self, message: &[u8], authenticated_data: &[u8]) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_hpke_sender_seal(
                self.handle.as_ptr(),
                message.as_ptr(),
                message.len(),
                authenticated_data.as_ptr(),
                authenticated_data.len(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Export an application secret from the HPKE sender context.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn export_secret(&self, context: &[u8], output_byte_count: usize) -> Result<SymmetricKey> {
        let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_hpke_sender_export_secret(
                self.handle.as_ptr(),
                context.as_ptr(),
                context.len(),
                output_byte_count,
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(SymmetricKey::from_bytes(bytes))
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        unsafe { ffi::ck_hpke_sender_release(self.handle.as_ptr()) };
    }
}

/// Stateful HPKE recipient context.
#[derive(Debug)]
pub struct Recipient {
    handle: NonNull<c_void>,
}

impl Recipient {
    /// Create a recipient for Diffie-Hellman private keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected ciphersuite is incompatible with the key type.
    pub fn new<K>(
        private_key: &K,
        ciphersuite: HpkeCiphersuite,
        info: &[u8],
        encapsulated_key: &[u8],
    ) -> Result<Self>
    where
        K: HpkeDiffieHellmanPrivateKeyImpl,
        K::PublicKey: HpkeDiffieHellmanPublicKey,
    {
        let private_key_bytes = private_key.hpke_private_key_bytes()?;
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_hpke_recipient_create_dh(
                private_key.hpke_dh_algorithm_ffi(),
                private_key_bytes.as_ptr(),
                private_key_bytes.len(),
                ciphersuite.kem.as_ffi(),
                ciphersuite.kdf.as_ffi(),
                ciphersuite.aead.as_ffi(),
                info.as_ptr(),
                info.len(),
                encapsulated_key.as_ptr(),
                encapsulated_key.len(),
                ffi::hpke_mode::BASE,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                &mut error,
            )
        };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Create a recipient with a pre-shared key for Diffie-Hellman private keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected ciphersuite is incompatible with the key type.
    pub fn new_with_psk<K>(
        private_key: &K,
        ciphersuite: HpkeCiphersuite,
        info: &[u8],
        encapsulated_key: &[u8],
        preshared_key: &SymmetricKey,
        preshared_key_identifier: &[u8],
    ) -> Result<Self>
    where
        K: HpkeDiffieHellmanPrivateKeyImpl,
        K::PublicKey: HpkeDiffieHellmanPublicKey,
    {
        let private_key_bytes = private_key.hpke_private_key_bytes()?;
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_hpke_recipient_create_dh(
                private_key.hpke_dh_algorithm_ffi(),
                private_key_bytes.as_ptr(),
                private_key_bytes.len(),
                ciphersuite.kem.as_ffi(),
                ciphersuite.kdf.as_ffi(),
                ciphersuite.aead.as_ffi(),
                info.as_ptr(),
                info.len(),
                encapsulated_key.as_ptr(),
                encapsulated_key.len(),
                ffi::hpke_mode::PSK,
                ptr::null(),
                0,
                preshared_key.as_bytes().as_ptr(),
                preshared_key.as_bytes().len(),
                preshared_key_identifier.as_ptr(),
                preshared_key_identifier.len(),
                &mut error,
            )
        };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Create an authenticated recipient for Diffie-Hellman private keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected ciphersuite is incompatible with the key type.
    pub fn new_authenticated<K>(
        private_key: &K,
        ciphersuite: HpkeCiphersuite,
        info: &[u8],
        encapsulated_key: &[u8],
        authentication_key: &K::PublicKey,
    ) -> Result<Self>
    where
        K: HpkeDiffieHellmanPrivateKeyImpl,
        K::PublicKey: HpkeDiffieHellmanPublicKeyImpl,
    {
        let private_key_bytes = private_key.hpke_private_key_bytes()?;
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_hpke_recipient_create_dh(
                private_key.hpke_dh_algorithm_ffi(),
                private_key_bytes.as_ptr(),
                private_key_bytes.len(),
                ciphersuite.kem.as_ffi(),
                ciphersuite.kdf.as_ffi(),
                ciphersuite.aead.as_ffi(),
                info.as_ptr(),
                info.len(),
                encapsulated_key.as_ptr(),
                encapsulated_key.len(),
                ffi::hpke_mode::AUTH,
                authentication_key.hpke_raw_public_key().as_ptr(),
                authentication_key.hpke_raw_public_key().len(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                &mut error,
            )
        };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Create an authenticated recipient with a pre-shared key for Diffie-Hellman private keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected ciphersuite is incompatible with the key type.
    pub fn new_authenticated_with_psk<K>(
        private_key: &K,
        ciphersuite: HpkeCiphersuite,
        info: &[u8],
        encapsulated_key: &[u8],
        authentication_key: &K::PublicKey,
        preshared_key: &SymmetricKey,
        preshared_key_identifier: &[u8],
    ) -> Result<Self>
    where
        K: HpkeDiffieHellmanPrivateKeyImpl,
        K::PublicKey: HpkeDiffieHellmanPublicKeyImpl,
    {
        let private_key_bytes = private_key.hpke_private_key_bytes()?;
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_hpke_recipient_create_dh(
                private_key.hpke_dh_algorithm_ffi(),
                private_key_bytes.as_ptr(),
                private_key_bytes.len(),
                ciphersuite.kem.as_ffi(),
                ciphersuite.kdf.as_ffi(),
                ciphersuite.aead.as_ffi(),
                info.as_ptr(),
                info.len(),
                encapsulated_key.as_ptr(),
                encapsulated_key.len(),
                ffi::hpke_mode::AUTH_PSK,
                authentication_key.hpke_raw_public_key().as_ptr(),
                authentication_key.hpke_raw_public_key().len(),
                preshared_key.as_bytes().as_ptr(),
                preshared_key.as_bytes().len(),
                preshared_key_identifier.as_ptr(),
                preshared_key_identifier.len(),
                &mut error,
            )
        };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Create a recipient for HPKE KEM private keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected ciphersuite is incompatible with the key type.
    pub fn new_with_kem<K>(
        private_key: &K,
        ciphersuite: HpkeCiphersuite,
        info: &[u8],
        encapsulated_key: &[u8],
    ) -> Result<Self>
    where
        K: HpkeKemPrivateKeyImpl,
        K::PublicKey: HpkeKemPublicKey,
    {
        let private_key_bytes = private_key.hpke_private_key_bytes()?;
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_hpke_recipient_create_kem(
                private_key.hpke_kem_algorithm_ffi(),
                private_key_bytes.as_ptr(),
                private_key_bytes.len(),
                ciphersuite.kem.as_ffi(),
                ciphersuite.kdf.as_ffi(),
                ciphersuite.aead.as_ffi(),
                info.as_ptr(),
                info.len(),
                encapsulated_key.as_ptr(),
                encapsulated_key.len(),
                &mut error,
            )
        };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Open a ciphertext without additional authenticated data.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.open_with_aad(ciphertext, &[])
    }

    /// Open a ciphertext with additional authenticated data.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn open_with_aad(
        &mut self,
        ciphertext: &[u8],
        authenticated_data: &[u8],
    ) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_hpke_recipient_open(
                self.handle.as_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                authenticated_data.as_ptr(),
                authenticated_data.len(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Export an application secret from the HPKE recipient context.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn export_secret(&self, context: &[u8], output_byte_count: usize) -> Result<SymmetricKey> {
        let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_hpke_recipient_export_secret(
                self.handle.as_ptr(),
                context.as_ptr(),
                context.len(),
                output_byte_count,
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(SymmetricKey::from_bytes(bytes))
    }
}

impl Drop for Recipient {
    fn drop(&mut self) {
        unsafe { ffi::ck_hpke_recipient_release(self.handle.as_ptr()) };
    }
}

macro_rules! impl_hpke_dh_public_key {
    ($type:ty, $algorithm:expr, $from:path, $raw:ident) => {
        impl HpkePublicKeySerialization for $type {
            fn from_hpke_serialization(serialization: &[u8], kem: HpkeKem) -> Result<Self> {
                let raw = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_hpke_dh_public_key_from_serialization(
                        $algorithm,
                        kem.as_ffi(),
                        serialization.as_ptr(),
                        serialization.len(),
                        out,
                        out_len,
                        error_out,
                    )
                })?;
                $from(raw)
            }

            fn hpke_representation(&self, kem: HpkeKem) -> Result<Vec<u8>> {
                bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_hpke_dh_public_key_representation(
                        $algorithm,
                        self.$raw().as_ptr(),
                        self.$raw().len(),
                        kem.as_ffi(),
                        out,
                        out_len,
                        error_out,
                    )
                })
            }
        }

        impl HpkeDiffieHellmanPublicKey for $type {}

        impl HpkeDiffieHellmanPublicKeyImpl for $type {
            fn hpke_dh_algorithm_ffi(&self) -> i32 {
                $algorithm
            }

            fn hpke_raw_public_key(&self) -> &[u8] {
                self.$raw()
            }
        }
    };
}

macro_rules! impl_hpke_dh_private_key {
    ($type:ty, $algorithm:expr, $raw:ident) => {
        impl HpkeDiffieHellmanPrivateKey for $type {}

        impl HpkeDiffieHellmanPrivateKeyGeneration for $type {
            fn generate() -> Result<Self> {
                <$type>::generate()
            }
        }

        impl HpkeDiffieHellmanPrivateKeyImpl for $type {
            fn hpke_dh_algorithm_ffi(&self) -> i32 {
                $algorithm
            }

            fn hpke_private_key_bytes(&self) -> Result<Vec<u8>> {
                Ok(self.$raw().to_vec())
            }
        }
    };
}

macro_rules! impl_hpke_kem_key {
    ($public_type:ty, $private_type:ty, $algorithm:expr, $public_from:path, $public_raw:ident, $private_raw:ident) => {
        impl HpkePublicKeySerialization for $public_type {
            fn from_hpke_serialization(serialization: &[u8], kem: HpkeKem) -> Result<Self> {
                let raw = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_hpke_kem_public_key_from_serialization(
                        $algorithm,
                        kem.as_ffi(),
                        serialization.as_ptr(),
                        serialization.len(),
                        out,
                        out_len,
                        error_out,
                    )
                })?;
                $public_from(raw)
            }

            fn hpke_representation(&self, kem: HpkeKem) -> Result<Vec<u8>> {
                bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_hpke_kem_public_key_representation(
                        $algorithm,
                        self.$public_raw().as_ptr(),
                        self.$public_raw().len(),
                        kem.as_ffi(),
                        out,
                        out_len,
                        error_out,
                    )
                })
            }
        }

        impl HpkeKemPublicKey for $public_type {}
        impl HpkeKemPrivateKey for $private_type {}
        impl HpkeKemPrivateKeyGeneration for $private_type {
            fn generate() -> Result<Self> {
                <$private_type>::generate()
            }
        }

        impl HpkeKemPublicKeyImpl for $public_type {
            fn hpke_kem_algorithm_ffi(&self) -> i32 {
                $algorithm
            }

            fn hpke_raw_public_key(&self) -> &[u8] {
                self.$public_raw()
            }
        }

        impl HpkeKemPrivateKeyImpl for $private_type {
            fn hpke_kem_algorithm_ffi(&self) -> i32 {
                $algorithm
            }

            fn hpke_private_key_bytes(&self) -> Result<Vec<u8>> {
                Ok(self.$private_raw().to_vec())
            }
        }
    };
}

impl_hpke_dh_public_key!(
    P256KeyAgreementPublicKey,
    ffi::key_agreement_algorithm::P256,
    P256KeyAgreementPublicKey::from_raw_representation,
    raw_representation
);
impl_hpke_dh_public_key!(
    P384KeyAgreementPublicKey,
    ffi::key_agreement_algorithm::P384,
    P384KeyAgreementPublicKey::from_raw_representation,
    raw_representation
);
impl_hpke_dh_public_key!(
    P521KeyAgreementPublicKey,
    ffi::key_agreement_algorithm::P521,
    P521KeyAgreementPublicKey::from_raw_representation,
    raw_representation
);
impl_hpke_dh_public_key!(
    X25519PublicKey,
    ffi::key_agreement_algorithm::X25519,
    X25519PublicKey::from_raw_representation,
    raw_representation
);

impl_hpke_dh_private_key!(
    P256KeyAgreementPrivateKey,
    ffi::key_agreement_algorithm::P256,
    raw_representation
);
impl_hpke_dh_private_key!(
    P384KeyAgreementPrivateKey,
    ffi::key_agreement_algorithm::P384,
    raw_representation
);
impl_hpke_dh_private_key!(
    P521KeyAgreementPrivateKey,
    ffi::key_agreement_algorithm::P521,
    raw_representation
);
impl_hpke_dh_private_key!(
    X25519PrivateKey,
    ffi::key_agreement_algorithm::X25519,
    raw_representation
);

impl_hpke_kem_key!(
    XWingMlkem768X25519PublicKey,
    XWingMlkem768X25519PrivateKey,
    ffi::kem_algorithm::XWING_MLKEM768_X25519,
    XWingMlkem768X25519PublicKey::from_raw_representation,
    raw_representation,
    integrity_checked_representation
);
