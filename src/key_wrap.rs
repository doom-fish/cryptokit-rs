//! AES key-wrap helpers.

use crate::error::Result;
use crate::ffi;
use crate::private::bridge_bytes;
use crate::symmetric::SymmetricKey;

/// AES key-wrap helpers backed by `CryptoKit.AES.KeyWrap`.
pub struct AesKeyWrap;

impl AesKeyWrap {
    /// Wrap a symmetric key using a key-encryption key (KEK).
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn wrap(key_to_wrap: &SymmetricKey, kek: &SymmetricKey) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_aes_key_wrap(
                key_to_wrap.as_bytes().as_ptr(),
                key_to_wrap.as_bytes().len(),
                kek.as_bytes().as_ptr(),
                kek.as_bytes().len(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Unwrap a wrapped symmetric key using a key-encryption key (KEK).
    ///
    /// # Errors
    ///
    /// Returns an error if the wrapped bytes are malformed or the Swift bridge rejects the request.
    pub fn unwrap(wrapped_key: &[u8], kek: &SymmetricKey) -> Result<SymmetricKey> {
        let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_aes_key_unwrap(
                wrapped_key.as_ptr(),
                wrapped_key.len(),
                kek.as_bytes().as_ptr(),
                kek.as_bytes().len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(SymmetricKey::from_bytes(bytes))
    }
}

/// Wrap a symmetric key using AES key-wrap.
///
/// # Errors
///
/// Returns an error if the Swift bridge rejects the request.
pub fn wrap(key_to_wrap: &SymmetricKey, kek: &SymmetricKey) -> Result<Vec<u8>> {
    AesKeyWrap::wrap(key_to_wrap, kek)
}

/// Unwrap a symmetric key using AES key-wrap.
///
/// # Errors
///
/// Returns an error if the wrapped bytes are malformed or the Swift bridge rejects the request.
pub fn unwrap(wrapped_key: &[u8], kek: &SymmetricKey) -> Result<SymmetricKey> {
    AesKeyWrap::unwrap(wrapped_key, kek)
}
