//! ML-DSA signing helpers.

use crate::error::Result;
use crate::ffi;
use crate::private::{bridge_bytes, bridge_flag};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum MldsaAlgorithm {
    Mldsa65,
    Mldsa87,
}

impl MldsaAlgorithm {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::Mldsa65 => ffi::mldsa_algorithm::MLDSA65,
            Self::Mldsa87 => ffi::mldsa_algorithm::MLDSA87,
        }
    }
}

macro_rules! mldsa_key_type {
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
            /// Returns an error if the bytes are invalid for this ML-DSA key.
            pub fn from_raw_representation(raw: impl Into<Vec<u8>>) -> Result<Self> {
                let raw = raw.into();
                let canonical = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_mldsa_public_key_validate(
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

            /// Verify a signature over message bytes.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
                self.verify_with_context(message, signature, None)
            }

            /// Verify a signature over message bytes with an explicit context.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn verify_with_context(
                &self,
                message: &[u8],
                signature: &[u8],
                context: Option<&[u8]>,
            ) -> Result<bool> {
                let context = context.unwrap_or(&[]);
                bridge_flag(|out_valid, error_out| unsafe {
                    ffi::ck_mldsa_public_key_verify(
                        $algorithm.as_ffi(),
                        self.raw.as_ptr(),
                        self.raw.len(),
                        signature.as_ptr(),
                        signature.len(),
                        message.as_ptr(),
                        message.len(),
                        context.as_ptr(),
                        context.len(),
                        out_valid,
                        error_out,
                    )
                })
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
                    ffi::ck_mldsa_private_key_from_seed(
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
                    ffi::ck_mldsa_private_key_validate(
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
                    ffi::ck_mldsa_private_key_seed_representation(
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

            /// Export the matching public key.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn public_key(&self) -> Result<$public_name> {
                let raw = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_mldsa_private_key_public_key(
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

            /// Sign a message.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
                self.sign_with_context(message, None)
            }

            /// Sign a message with an explicit context.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn sign_with_context(
                &self,
                message: &[u8],
                context: Option<&[u8]>,
            ) -> Result<Vec<u8>> {
                let context = context.unwrap_or(&[]);
                bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_mldsa_private_key_sign(
                        $algorithm.as_ffi(),
                        self.integrity_checked.as_ptr(),
                        self.integrity_checked.len(),
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

            /// Generate a fresh private key.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn generate() -> Result<Self> {
                let integrity_checked = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_mldsa_private_key_generate($algorithm.as_ffi(), out, out_len, error_out)
                })?;
                Ok(Self { integrity_checked })
            }
        }
    };
}

mldsa_key_type!(
    Mldsa65PublicKey,
    Mldsa65PrivateKey,
    MldsaAlgorithm::Mldsa65,
    "An ML-DSA-65 public key.",
    "An ML-DSA-65 private key."
);
mldsa_key_type!(
    Mldsa87PublicKey,
    Mldsa87PrivateKey,
    MldsaAlgorithm::Mldsa87,
    "An ML-DSA-87 public key.",
    "An ML-DSA-87 private key."
);
