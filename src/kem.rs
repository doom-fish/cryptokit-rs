//! Key-encapsulation mechanism helpers.

use crate::error::Result;
use crate::ffi;
use crate::private::{bridge_bytes, bridge_two_buffers};
use crate::symmetric::SymmetricKey;

/// A successful KEM encapsulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncapsulationResult {
    shared_secret: SymmetricKey,
    encapsulated: Vec<u8>,
}

impl EncapsulationResult {
    pub(crate) const fn new(shared_secret: SymmetricKey, encapsulated: Vec<u8>) -> Self {
        Self {
            shared_secret,
            encapsulated,
        }
    }

    /// Borrow the derived shared secret.
    #[must_use]
    pub const fn shared_secret(&self) -> &SymmetricKey {
        &self.shared_secret
    }

    /// Consume the encapsulation result and return the shared secret.
    #[must_use]
    pub fn into_shared_secret(self) -> SymmetricKey {
        self.shared_secret
    }

    /// Borrow the encapsulated key bytes.
    #[must_use]
    pub fn encapsulated(&self) -> &[u8] {
        &self.encapsulated
    }

    /// Consume the encapsulation result and return the encapsulated key bytes.
    #[must_use]
    pub fn into_encapsulated(self) -> Vec<u8> {
        self.encapsulated
    }
}

/// Cases currently defined by `CryptoKit.KEM.Errors`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KemError {
    PublicKeyMismatchDuringInitialization,
    InvalidSeed,
}

/// Trait mirroring `CryptoKit.KEMPublicKey`.
pub trait KemPublicKey {
    /// Encapsulate a fresh shared secret to this public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    fn encapsulate(&self) -> Result<EncapsulationResult>;
}

/// Trait mirroring `CryptoKit.KEMPrivateKey`.
pub trait KemPrivateKey: Sized {
    /// Public-key type associated with this private key.
    type PublicKey: KemPublicKey;

    /// Generate a fresh private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    fn generate() -> Result<Self>;

    /// Derive or export the matching public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    fn public_key(&self) -> Result<Self::PublicKey>;

    /// Decapsulate a peer's encapsulated key.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    fn decapsulate(&self, encapsulated: &[u8]) -> Result<SymmetricKey>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum KemAlgorithm {
    Mlkem768,
    Mlkem1024,
    XWingMlkem768X25519,
}

impl KemAlgorithm {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::Mlkem768 => ffi::kem_algorithm::MLKEM768,
            Self::Mlkem1024 => ffi::kem_algorithm::MLKEM1024,
            Self::XWingMlkem768X25519 => ffi::kem_algorithm::XWING_MLKEM768_X25519,
        }
    }
}

macro_rules! kem_key_type {
    ($public_name:ident, $private_name:ident, $algorithm:expr, $public_doc:literal, $private_doc:literal) => {
        #[doc = $public_doc]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $public_name {
            raw: Vec<u8>,
        }

        impl $public_name {
            /// Validate and wrap a raw public-key representation.
            ///
            /// # Errors
            ///
            /// Returns an error if the bytes are invalid for this KEM.
            pub fn from_raw_representation(raw: impl Into<Vec<u8>>) -> Result<Self> {
                let raw = raw.into();
                let canonical = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_kem_public_key_validate(
                        $algorithm.as_ffi(),
                        raw.as_ptr(),
                        raw.len(),
                        out,
                        out_len,
                        error_out,
                    )
                })?;
                Ok(Self { raw: canonical })
            }

            /// Borrow the raw public-key representation.
            #[must_use]
            pub fn raw_representation(&self) -> &[u8] {
                &self.raw
            }

            /// Consume the key and return its raw representation.
            #[must_use]
            pub fn into_raw_representation(self) -> Vec<u8> {
                self.raw
            }

            /// Encapsulate a fresh shared secret to this public key.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn encapsulate(&self) -> Result<EncapsulationResult> {
                let (shared_secret, encapsulated) = bridge_two_buffers(
                    |shared_secret_out,
                     shared_secret_out_len,
                     encapsulated_out,
                     encapsulated_out_len,
                     error_out| unsafe {
                        ffi::ck_kem_public_key_encapsulate(
                            $algorithm.as_ffi(),
                            self.raw.as_ptr(),
                            self.raw.len(),
                            shared_secret_out,
                            shared_secret_out_len,
                            encapsulated_out,
                            encapsulated_out_len,
                            error_out,
                        )
                    },
                )?;
                Ok(EncapsulationResult::new(
                    SymmetricKey::from_bytes(shared_secret),
                    encapsulated,
                ))
            }
        }

        impl KemPublicKey for $public_name {
            fn encapsulate(&self) -> Result<EncapsulationResult> {
                self.encapsulate()
            }
        }

        #[doc = $private_doc]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $private_name {
            integrity_checked: Vec<u8>,
        }

        impl $private_name {
            /// Construct a private key from its seed representation.
            ///
            /// # Errors
            ///
            /// Returns an error if the seed bytes are invalid.
            pub fn from_seed_representation(
                seed: impl Into<Vec<u8>>,
                public_key: Option<&$public_name>,
            ) -> Result<Self> {
                let seed = seed.into();
                let public_key_bytes = public_key
                    .map(|value| value.raw_representation())
                    .unwrap_or_default();
                let integrity_checked = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_kem_private_key_from_seed(
                        $algorithm.as_ffi(),
                        seed.as_ptr(),
                        seed.len(),
                        public_key_bytes.as_ptr(),
                        public_key_bytes.len(),
                        out,
                        out_len,
                        error_out,
                    )
                })?;
                Ok(Self { integrity_checked })
            }

            /// Validate and wrap an integrity-checked private-key representation.
            ///
            /// # Errors
            ///
            /// Returns an error if the bytes are invalid.
            pub fn from_integrity_checked_representation(
                integrity_checked: impl Into<Vec<u8>>,
            ) -> Result<Self> {
                let integrity_checked = integrity_checked.into();
                let canonical = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_kem_private_key_validate(
                        $algorithm.as_ffi(),
                        integrity_checked.as_ptr(),
                        integrity_checked.len(),
                        out,
                        out_len,
                        error_out,
                    )
                })?;
                Ok(Self {
                    integrity_checked: canonical,
                })
            }

            /// Export the seed representation.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn seed_representation(&self) -> Result<Vec<u8>> {
                bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_kem_private_key_seed_representation(
                        $algorithm.as_ffi(),
                        self.integrity_checked.as_ptr(),
                        self.integrity_checked.len(),
                        out,
                        out_len,
                        error_out,
                    )
                })
            }

            /// Borrow the integrity-checked representation.
            #[must_use]
            pub fn integrity_checked_representation(&self) -> &[u8] {
                &self.integrity_checked
            }

            /// Consume the key and return its integrity-checked representation.
            #[must_use]
            pub fn into_integrity_checked_representation(self) -> Vec<u8> {
                self.integrity_checked
            }

            /// Generate a fresh private key.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn generate() -> Result<Self> {
                let integrity_checked = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_kem_private_key_generate($algorithm.as_ffi(), out, out_len, error_out)
                })?;
                Ok(Self { integrity_checked })
            }

            /// Export the matching public key.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn public_key(&self) -> Result<$public_name> {
                let raw = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_kem_private_key_public_key(
                        $algorithm.as_ffi(),
                        self.integrity_checked.as_ptr(),
                        self.integrity_checked.len(),
                        out,
                        out_len,
                        error_out,
                    )
                })?;
                $public_name::from_raw_representation(raw)
            }

            /// Decapsulate an encapsulated key.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn decapsulate(&self, encapsulated: &[u8]) -> Result<SymmetricKey> {
                let shared_secret = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_kem_private_key_decapsulate(
                        $algorithm.as_ffi(),
                        self.integrity_checked.as_ptr(),
                        self.integrity_checked.len(),
                        encapsulated.as_ptr(),
                        encapsulated.len(),
                        out,
                        out_len,
                        error_out,
                    )
                })?;
                Ok(SymmetricKey::from_bytes(shared_secret))
            }
        }

        impl KemPrivateKey for $private_name {
            type PublicKey = $public_name;

            fn generate() -> Result<Self> {
                Self::generate()
            }

            fn public_key(&self) -> Result<Self::PublicKey> {
                self.public_key()
            }

            fn decapsulate(&self, encapsulated: &[u8]) -> Result<SymmetricKey> {
                self.decapsulate(encapsulated)
            }
        }
    };
}

kem_key_type!(
    Mlkem768PublicKey,
    Mlkem768PrivateKey,
    KemAlgorithm::Mlkem768,
    "An ML-KEM-768 public key.",
    "An ML-KEM-768 private key."
);
kem_key_type!(
    Mlkem1024PublicKey,
    Mlkem1024PrivateKey,
    KemAlgorithm::Mlkem1024,
    "An ML-KEM-1024 public key.",
    "An ML-KEM-1024 private key."
);
kem_key_type!(
    XWingMlkem768X25519PublicKey,
    XWingMlkem768X25519PrivateKey,
    KemAlgorithm::XWingMlkem768X25519,
    "An X-Wing ML-KEM-768/X25519 hybrid public key.",
    "An X-Wing ML-KEM-768/X25519 hybrid private key."
);
