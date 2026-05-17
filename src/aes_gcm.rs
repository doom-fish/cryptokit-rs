//! Rich AES-GCM wrappers with authenticated data and sealed-box accessors.

use crate::error::{CryptoKitError, Result};
use crate::ffi;
use crate::private::{bridge_bytes, hex, validate_byte_count};
use crate::symmetric::SymmetricKey;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Typed AES-GCM nonce bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AesGcmNonce(Vec<u8>);

impl AesGcmNonce {
    /// Number of bytes in an AES-GCM nonce.
    pub const BYTE_COUNT: usize = NONCE_LEN;

    /// Generate a fresh AES-GCM nonce via `CryptoKit`.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn generate() -> Result<Self> {
        Self::from_bytes(bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_aes_gcm_nonce_generate(out, out_len, error_out)
        })?)
    }

    /// Validate and wrap nonce bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the nonce is not exactly 12 bytes long.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(validate_byte_count(
            "AesGcmNonce",
            Self::BYTE_COUNT,
            bytes.into(),
        )?))
    }

    /// Borrow the nonce bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the nonce and return its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for AesGcmNonce {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::fmt::Display for AesGcmNonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&hex(self.as_bytes()))
    }
}

/// Combined AES-GCM payload in `nonce || ciphertext || tag` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesGcmSealedBox {
    combined: Vec<u8>,
}

impl AesGcmSealedBox {
    /// Validate and wrap a combined AES-GCM representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is shorter than `nonce || tag`.
    pub fn from_combined(combined: impl Into<Vec<u8>>) -> Result<Self> {
        let combined = combined.into();
        if combined.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoKitError::InvalidArgument(
                "AES-GCM combined payload must contain at least a nonce and tag".to_owned(),
            ));
        }
        Ok(Self { combined })
    }

    /// Build a sealed box from individual nonce, ciphertext, and tag components.
    ///
    /// # Errors
    ///
    /// Returns an error if the tag is not exactly 16 bytes long.
    pub fn from_parts(nonce: &AesGcmNonce, ciphertext: &[u8], tag: &[u8]) -> Result<Self> {
        if tag.len() != TAG_LEN {
            return Err(CryptoKitError::InvalidArgument(
                "AES-GCM tags must be 16 bytes".to_owned(),
            ));
        }

        let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
        combined.extend_from_slice(nonce.as_bytes());
        combined.extend_from_slice(ciphertext);
        combined.extend_from_slice(tag);
        Ok(Self { combined })
    }

    /// Borrow the combined representation.
    #[must_use]
    pub fn combined(&self) -> &[u8] {
        &self.combined
    }

    /// Consume the sealed box and return the combined representation.
    #[must_use]
    pub fn into_combined(self) -> Vec<u8> {
        self.combined
    }

    /// Borrow the 12-byte nonce prefix.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.combined[..NONCE_LEN]
    }

    /// Return the typed nonce value.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored nonce bytes are malformed.
    pub fn nonce_value(&self) -> Result<AesGcmNonce> {
        AesGcmNonce::from_bytes(self.nonce().to_vec())
    }

    /// Borrow the ciphertext portion.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.combined[NONCE_LEN..self.combined.len() - TAG_LEN]
    }

    /// Borrow the 16-byte authentication tag suffix.
    #[must_use]
    pub fn tag(&self) -> &[u8] {
        &self.combined[self.combined.len() - TAG_LEN..]
    }
}

/// AES-GCM authenticated encryption with optional authenticated data.
pub struct AesGcm;

impl AesGcm {
    /// Encrypt a message with AES-GCM and return a parsed sealed box.
    ///
    /// # Errors
    ///
    /// Returns an error if the nonce length is invalid or the Swift bridge rejects the request.
    pub fn seal(
        message: &[u8],
        key: &SymmetricKey,
        nonce: Option<&[u8]>,
    ) -> Result<AesGcmSealedBox> {
        Self::seal_with_aad(message, key, nonce, &[])
    }

    /// Encrypt a message with AES-GCM using a typed nonce.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn seal_with_nonce(
        message: &[u8],
        key: &SymmetricKey,
        nonce: &AesGcmNonce,
    ) -> Result<AesGcmSealedBox> {
        Self::seal_with_aad(message, key, Some(nonce.as_bytes()), &[])
    }

    /// Encrypt a message with AES-GCM while authenticating additional data.
    ///
    /// # Errors
    ///
    /// Returns an error if the nonce length is invalid or the Swift bridge rejects the request.
    pub fn seal_with_aad(
        message: &[u8],
        key: &SymmetricKey,
        nonce: Option<&[u8]>,
        authenticated_data: &[u8],
    ) -> Result<AesGcmSealedBox> {
        if let Some(nonce) = nonce {
            if nonce.len() != NONCE_LEN {
                return Err(CryptoKitError::InvalidArgument(
                    "AES-GCM nonces must be 12 bytes".to_owned(),
                ));
            }
        }

        let nonce = nonce.unwrap_or(&[]);
        let combined = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_aes_gcm_seal_aad(
                key.as_bytes().as_ptr(),
                key.as_bytes().len(),
                message.as_ptr(),
                message.len(),
                nonce.as_ptr(),
                nonce.len(),
                authenticated_data.as_ptr(),
                authenticated_data.len(),
                out,
                out_len,
                error_out,
            )
        })?;
        AesGcmSealedBox::from_combined(combined)
    }

    /// Encrypt a message with AES-GCM using a typed nonce and authenticated data.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn seal_with_nonce_and_aad(
        message: &[u8],
        key: &SymmetricKey,
        nonce: &AesGcmNonce,
        authenticated_data: &[u8],
    ) -> Result<AesGcmSealedBox> {
        Self::seal_with_aad(message, key, Some(nonce.as_bytes()), authenticated_data)
    }

    /// Decrypt a sealed box produced by [`Self::seal`].
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn open(sealed_box: &AesGcmSealedBox, key: &SymmetricKey) -> Result<Vec<u8>> {
        Self::open_with_aad(sealed_box, key, &[])
    }

    /// Decrypt a sealed box while validating authenticated data.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn open_with_aad(
        sealed_box: &AesGcmSealedBox,
        key: &SymmetricKey,
        authenticated_data: &[u8],
    ) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_aes_gcm_open_aad(
                key.as_bytes().as_ptr(),
                key.as_bytes().len(),
                sealed_box.combined().as_ptr(),
                sealed_box.combined().len(),
                authenticated_data.as_ptr(),
                authenticated_data.len(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Compatibility helper returning the combined representation directly.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn seal_combined(
        message: &[u8],
        key: &SymmetricKey,
        nonce: Option<&[u8]>,
        authenticated_data: &[u8],
    ) -> Result<Vec<u8>> {
        Ok(Self::seal_with_aad(message, key, nonce, authenticated_data)?.into_combined())
    }
}
