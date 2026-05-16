//! AES-CBC compatibility wrappers backed by the Swift bridge.

use crate::error::{CryptoKitError, Result};
use crate::ffi;
use crate::private::bridge_bytes;
use crate::symmetric::SymmetricKey;

const BLOCK_LEN: usize = 16;

/// AES-CBC encryption and decryption with PKCS#7 padding.
pub struct AesCbc;

impl AesCbc {
    /// Encrypt plaintext with PKCS#7 padding.
    ///
    /// # Errors
    ///
    /// Returns an error if the key length or IV length is invalid.
    pub fn encrypt_pkcs7(plaintext: &[u8], key: &SymmetricKey, iv: &[u8]) -> Result<Vec<u8>> {
        validate_key_and_iv(key, iv)?;
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_aes_cbc_encrypt(
                key.as_bytes().as_ptr(),
                key.as_bytes().len(),
                iv.as_ptr(),
                iv.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Decrypt ciphertext with PKCS#7 padding.
    ///
    /// # Errors
    ///
    /// Returns an error if the key length or IV length is invalid, or if padding is invalid.
    pub fn decrypt_pkcs7(ciphertext: &[u8], key: &SymmetricKey, iv: &[u8]) -> Result<Vec<u8>> {
        validate_key_and_iv(key, iv)?;
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_aes_cbc_decrypt(
                key.as_bytes().as_ptr(),
                key.as_bytes().len(),
                iv.as_ptr(),
                iv.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                out,
                out_len,
                error_out,
            )
        })
    }
}

fn validate_key_and_iv(key: &SymmetricKey, iv: &[u8]) -> Result<()> {
    match key.as_bytes().len() {
        16 | 24 | 32 => {}
        _ => {
            return Err(CryptoKitError::InvalidArgument(
                "AES-CBC keys must be 16, 24, or 32 bytes".to_owned(),
            ));
        }
    }

    if iv.len() != BLOCK_LEN {
        return Err(CryptoKitError::InvalidArgument(
            "AES-CBC IVs must be 16 bytes".to_owned(),
        ));
    }

    Ok(())
}
