//! Secure Enclave-backed P-256 keys.

use core::ffi::{c_char, c_void};
use std::ptr;
use std::ptr::NonNull;

use crate::error::{from_swift, Result};
use crate::ffi;
use crate::kem::{KemAlgorithm, Mlkem1024PublicKey, Mlkem768PublicKey};
use crate::key_agreement::DiffieHellmanKeyAgreement;
use crate::mldsa::{Mldsa65PublicKey, Mldsa87PublicKey, MldsaAlgorithm};
use crate::p256::{P256EcdsaSignature, P256KeyAgreementPublicKey, P256SigningPublicKey};
use crate::private::{bridge_bytes, bridge_flag};
use crate::public_key::SharedSecret;
use crate::symmetric::SymmetricKey;

/// Query whether the current machine reports Secure Enclave availability.
///
/// # Errors
///
/// Returns an error if the Swift bridge rejects the query.
pub fn is_available() -> Result<bool> {
    bridge_flag(|out_available, error_out| unsafe {
        ffi::ck_secure_enclave_is_available(out_available, error_out)
    })
}

/// A Secure Enclave-backed P-256 signing private key.
#[derive(Debug)]
pub struct SecureEnclaveSigningPrivateKey {
    handle: NonNull<c_void>,
}

impl SecureEnclaveSigningPrivateKey {
    /// Generate a new Secure Enclave signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or key creation fails.
    pub fn generate() -> Result<Self> {
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe { ffi::ck_secure_enclave_signing_private_key_generate(&mut error) };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Restore a Secure Enclave signing key from its persisted data representation.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or the persisted bytes are invalid.
    pub fn from_data_representation(data_representation: &[u8]) -> Result<Self> {
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_secure_enclave_signing_private_key_from_data_representation(
                data_representation.as_ptr(),
                data_representation.len(),
                &mut error,
            )
        };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Export the persisted data representation for later restoration.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn data_representation(&self) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_signing_private_key_data_representation(
                self.handle.as_ptr(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Export the matching software-verifiable P-256 public key.
    ///
    /// # Errors
    ///
    /// Returns an error if public-key export fails.
    pub fn public_key(&self) -> Result<P256SigningPublicKey> {
        let raw = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_signing_private_key_public_key(
                self.handle.as_ptr(),
                out,
                out_len,
                error_out,
            )
        })?;
        P256SigningPublicKey::from_raw_representation(raw)
    }

    /// Sign a message with the Secure Enclave key.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_signing_private_key_sign(
                self.handle.as_ptr(),
                message.as_ptr(),
                message.len(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Sign a message and return a typed P-256 ECDSA signature.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_signature(&self, message: &[u8]) -> Result<P256EcdsaSignature> {
        P256EcdsaSignature::from_raw_representation(self.sign(message)?)
    }
}

impl Drop for SecureEnclaveSigningPrivateKey {
    fn drop(&mut self) {
        unsafe { ffi::ck_secure_enclave_signing_private_key_release(self.handle.as_ptr()) };
    }
}

/// A Secure Enclave-backed P-256 key-agreement private key.
#[derive(Debug)]
pub struct SecureEnclaveKeyAgreementPrivateKey {
    handle: NonNull<c_void>,
}

impl SecureEnclaveKeyAgreementPrivateKey {
    /// Generate a new Secure Enclave key-agreement key.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or key creation fails.
    pub fn generate() -> Result<Self> {
        let mut error: *mut c_char = ptr::null_mut();
        let handle =
            unsafe { ffi::ck_secure_enclave_key_agreement_private_key_generate(&mut error) };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Restore a Secure Enclave key-agreement key from its persisted data representation.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or the persisted bytes are invalid.
    pub fn from_data_representation(data_representation: &[u8]) -> Result<Self> {
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_secure_enclave_key_agreement_private_key_from_data_representation(
                data_representation.as_ptr(),
                data_representation.len(),
                &mut error,
            )
        };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Export the persisted data representation for later restoration.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn data_representation(&self) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_key_agreement_private_key_data_representation(
                self.handle.as_ptr(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Export the matching software-verifiable P-256 public key.
    ///
    /// # Errors
    ///
    /// Returns an error if public-key export fails.
    pub fn public_key(&self) -> Result<P256KeyAgreementPublicKey> {
        let raw = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_key_agreement_private_key_public_key(
                self.handle.as_ptr(),
                out,
                out_len,
                error_out,
            )
        })?;
        P256KeyAgreementPublicKey::from_raw_representation(raw)
    }

    /// Derive a shared secret with a software P-256 public key.
    ///
    /// # Errors
    ///
    /// Returns an error if key agreement fails.
    pub fn shared_secret(&self, peer: &P256KeyAgreementPublicKey) -> Result<SharedSecret> {
        let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_key_agreement_private_key_shared_secret(
                self.handle.as_ptr(),
                peer.raw_representation().as_ptr(),
                peer.raw_representation().len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(SharedSecret::from_bytes(bytes))
    }
}

impl Drop for SecureEnclaveKeyAgreementPrivateKey {
    fn drop(&mut self) {
        unsafe { ffi::ck_secure_enclave_key_agreement_private_key_release(self.handle.as_ptr()) };
    }
}

impl DiffieHellmanKeyAgreement for SecureEnclaveKeyAgreementPrivateKey {
    type PublicKey = P256KeyAgreementPublicKey;

    fn public_key(&self) -> Result<Self::PublicKey> {
        Self::public_key(self)
    }

    fn shared_secret(&self, public_key: &Self::PublicKey) -> Result<SharedSecret> {
        Self::shared_secret(self, public_key)
    }
}

macro_rules! secure_enclave_mldsa_key {
    ($name:ident, $public_name:ident, $algorithm:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name {
            handle: NonNull<c_void>,
        }

        impl $name {
            /// Generate a new Secure Enclave private key.
            ///
            /// # Errors
            ///
            /// Returns an error if Secure Enclave is unavailable or key creation fails.
            pub fn generate() -> Result<Self> {
                let mut error: *mut c_char = ptr::null_mut();
                let handle = unsafe {
                    ffi::ck_secure_enclave_mldsa_private_key_generate($algorithm.as_ffi(), &mut error)
                };
                let handle =
                    NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
                Ok(Self { handle })
            }

            /// Restore a Secure Enclave private key from its persisted data representation.
            ///
            /// # Errors
            ///
            /// Returns an error if Secure Enclave is unavailable or the bytes are invalid.
            pub fn from_data_representation(data_representation: &[u8]) -> Result<Self> {
                let mut error: *mut c_char = ptr::null_mut();
                let handle = unsafe {
                    ffi::ck_secure_enclave_mldsa_private_key_from_data_representation(
                        $algorithm.as_ffi(),
                        data_representation.as_ptr(),
                        data_representation.len(),
                        &mut error,
                    )
                };
                let handle =
                    NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
                Ok(Self { handle })
            }

            /// Export the persisted data representation for later restoration.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn data_representation(&self) -> Result<Vec<u8>> {
                bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_secure_enclave_mldsa_private_key_data_representation(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                        out,
                        out_len,
                        error_out,
                    )
                })
            }

            /// Export the matching software-verifiable public key.
            ///
            /// # Errors
            ///
            /// Returns an error if public-key export fails.
            pub fn public_key(&self) -> Result<$public_name> {
                let raw = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_secure_enclave_mldsa_private_key_public_key(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                        out,
                        out_len,
                        error_out,
                    )
                })?;
                $public_name::from_raw_representation(raw)
            }

            /// Sign a message.
            ///
            /// # Errors
            ///
            /// Returns an error if signing fails.
            pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
                self.sign_with_context(message, None)
            }

            /// Sign a message with an explicit ML-DSA context.
            ///
            /// # Errors
            ///
            /// Returns an error if signing fails.
            pub fn sign_with_context(
                &self,
                message: &[u8],
                context: Option<&[u8]>,
            ) -> Result<Vec<u8>> {
                let context = context.unwrap_or(&[]);
                bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_secure_enclave_mldsa_private_key_sign(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                        message.as_ptr(),
                        message.len(),
                        context.as_ptr(),
                        context.len(),
                        out,
                        out_len,
                        error_out,
                    )
                })
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe {
                    ffi::ck_secure_enclave_mldsa_private_key_release(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                    )
                };
            }
        }
    };
}

macro_rules! secure_enclave_kem_key {
    ($name:ident, $public_name:ident, $algorithm:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name {
            handle: NonNull<c_void>,
        }

        impl $name {
            /// Generate a new Secure Enclave private key.
            ///
            /// # Errors
            ///
            /// Returns an error if Secure Enclave is unavailable or key creation fails.
            pub fn generate() -> Result<Self> {
                let mut error: *mut c_char = ptr::null_mut();
                let handle = unsafe {
                    ffi::ck_secure_enclave_kem_private_key_generate($algorithm.as_ffi(), &mut error)
                };
                let handle =
                    NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
                Ok(Self { handle })
            }

            /// Restore a Secure Enclave private key from its persisted data representation.
            ///
            /// # Errors
            ///
            /// Returns an error if Secure Enclave is unavailable or the bytes are invalid.
            pub fn from_data_representation(data_representation: &[u8]) -> Result<Self> {
                let mut error: *mut c_char = ptr::null_mut();
                let handle = unsafe {
                    ffi::ck_secure_enclave_kem_private_key_from_data_representation(
                        $algorithm.as_ffi(),
                        data_representation.as_ptr(),
                        data_representation.len(),
                        &mut error,
                    )
                };
                let handle =
                    NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
                Ok(Self { handle })
            }

            /// Export the persisted data representation for later restoration.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn data_representation(&self) -> Result<Vec<u8>> {
                bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_secure_enclave_kem_private_key_data_representation(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                        out,
                        out_len,
                        error_out,
                    )
                })
            }

            /// Export the matching software public key.
            ///
            /// # Errors
            ///
            /// Returns an error if public-key export fails.
            pub fn public_key(&self) -> Result<$public_name> {
                let raw = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_secure_enclave_kem_private_key_public_key(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
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
            /// Returns an error if decapsulation fails.
            pub fn decapsulate(&self, encapsulated: &[u8]) -> Result<SymmetricKey> {
                let shared_secret = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_secure_enclave_kem_private_key_decapsulate(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
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

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe {
                    ffi::ck_secure_enclave_kem_private_key_release(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                    )
                };
            }
        }
    };
}

secure_enclave_mldsa_key!(
    SecureEnclaveMldsa65PrivateKey,
    Mldsa65PublicKey,
    MldsaAlgorithm::Mldsa65,
    "A Secure Enclave-backed ML-DSA-65 private key."
);
secure_enclave_mldsa_key!(
    SecureEnclaveMldsa87PrivateKey,
    Mldsa87PublicKey,
    MldsaAlgorithm::Mldsa87,
    "A Secure Enclave-backed ML-DSA-87 private key."
);
secure_enclave_kem_key!(
    SecureEnclaveMlkem768PrivateKey,
    Mlkem768PublicKey,
    KemAlgorithm::Mlkem768,
    "A Secure Enclave-backed ML-KEM-768 private key."
);
secure_enclave_kem_key!(
    SecureEnclaveMlkem1024PrivateKey,
    Mlkem1024PublicKey,
    KemAlgorithm::Mlkem1024,
    "A Secure Enclave-backed ML-KEM-1024 private key."
);
