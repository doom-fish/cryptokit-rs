//! Symmetric keys and AEAD ciphers.

use crate::error::{CryptoKitError, Result};
use crate::ffi;
use crate::private::bridge_bytes;

/// Supported symmetric-key sizes for generated keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SymmetricKeySize {
    Bits128,
    Bits192,
    Bits256,
}

impl SymmetricKeySize {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::Bits128 => 128,
            Self::Bits192 => 192,
            Self::Bits256 => 256,
        }
    }
}

/// Opaque symmetric key material stored as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymmetricKey {
    bytes: Vec<u8>,
}

impl SymmetricKey {
    /// Generate a fresh symmetric key of the requested size.
    ///
    /// # Errors
    ///
    /// Returns an error if the `CryptoKit` bridge rejects the request.
    pub fn generate(size: SymmetricKeySize) -> Result<Self> {
        let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_symmetric_key_generate(size.as_ffi(), out, out_len, error_out)
        })?;
        Ok(Self { bytes })
    }

    /// Wrap existing symmetric key bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Borrow the underlying key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the key and return its underlying bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Length of the key in bits.
    #[must_use]
    pub fn bits(&self) -> usize {
        self.bytes.len() * 8
    }
}

/// AES-GCM authenticated encryption with combined output.
pub struct AesGcm;

impl AesGcm {
    /// Encrypt a message, returning `CryptoKit`'s combined `nonce || ciphertext || tag` form.
    ///
    /// # Errors
    ///
    /// Returns an error if the nonce length is invalid or the `CryptoKit` bridge rejects the request.
    pub fn seal(message: &[u8], key: &SymmetricKey, nonce: Option<&[u8]>) -> Result<Vec<u8>> {
        if let Some(nonce) = nonce {
            if nonce.len() != 12 {
                return Err(CryptoKitError::InvalidArgument(
                    "AES-GCM nonces must be 12 bytes".to_owned(),
                ));
            }
        }

        let nonce = nonce.unwrap_or(&[]);
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_aes_gcm_seal(
                key.as_bytes().as_ptr(),
                key.as_bytes().len(),
                message.as_ptr(),
                message.len(),
                nonce.as_ptr(),
                nonce.len(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Decrypt a combined AES-GCM payload returned by [`Self::seal`].
    ///
    /// # Errors
    ///
    /// Returns an error if the `CryptoKit` bridge rejects the request.
    pub fn open(combined: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_aes_gcm_open(
                key.as_bytes().as_ptr(),
                key.as_bytes().len(),
                combined.as_ptr(),
                combined.len(),
                out,
                out_len,
                error_out,
            )
        })
    }
}

/// ChaCha20-Poly1305 authenticated encryption with combined output.
pub struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {
    /// Encrypt a message, returning `CryptoKit`'s combined `nonce || ciphertext || tag` form.
    ///
    /// # Errors
    ///
    /// Returns an error if the nonce length is invalid or the `CryptoKit` bridge rejects the request.
    pub fn seal(message: &[u8], key: &SymmetricKey, nonce: Option<&[u8]>) -> Result<Vec<u8>> {
        if let Some(nonce) = nonce {
            if nonce.len() != 12 {
                return Err(CryptoKitError::InvalidArgument(
                    "ChaCha20-Poly1305 nonces must be 12 bytes".to_owned(),
                ));
            }
        }

        let nonce = nonce.unwrap_or(&[]);
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_chacha_poly_seal(
                key.as_bytes().as_ptr(),
                key.as_bytes().len(),
                message.as_ptr(),
                message.len(),
                nonce.as_ptr(),
                nonce.len(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Decrypt a combined ChaCha20-Poly1305 payload returned by [`Self::seal`].
    ///
    /// # Errors
    ///
    /// Returns an error if the `CryptoKit` bridge rejects the request.
    pub fn open(combined: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_chacha_poly_open(
                key.as_bytes().as_ptr(),
                key.as_bytes().len(),
                combined.as_ptr(),
                combined.len(),
                out,
                out_len,
                error_out,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{AesGcm, CryptoKitError, Result, SymmetricKey};

    #[test]
    fn aes_gcm_round_trips_with_explicit_nonce() -> Result<()> {
        let key = SymmetricKey::from_bytes(vec![0x11; 32]);
        let message = [0x41_u8; 16];
        let nonce = [0_u8; 12];

        let sealed = AesGcm::seal(&message, &key, Some(&nonce))?;
        assert_eq!(sealed.len(), 44);
        assert_eq!(AesGcm::open(&sealed, &key)?, message);
        Ok(())
    }

    #[test]
    fn aes_gcm_rejects_invalid_nonce_lengths() {
        let key = SymmetricKey::from_bytes(vec![0x22; 32]);
        let result = AesGcm::seal(b"hello", &key, Some(&[0_u8; 11]));
        assert!(matches!(result, Err(CryptoKitError::InvalidArgument(_))));
    }
}
