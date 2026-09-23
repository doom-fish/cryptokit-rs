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
    /// Returns an error if the key or IV length is invalid or the ciphertext is not a whole
    /// number of blocks. Every decryption failure yields the same error, and `CommonCrypto`
    /// does not reliably reject malformed padding, so authenticate ciphertexts separately.
    pub fn decrypt_pkcs7(ciphertext: &[u8], key: &SymmetricKey, iv: &[u8]) -> Result<Vec<u8>> {
        validate_key_and_iv(key, iv)?;
        if ciphertext.is_empty() || ciphertext.len() % BLOCK_LEN != 0 {
            return Err(decryption_failed());
        }
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
        .map_err(|_| decryption_failed())
    }
}

fn decryption_failed() -> CryptoKitError {
    CryptoKitError::DecryptionFailed("AES-CBC decryption failed".to_owned())
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

#[cfg(test)]
mod tests {
    use super::{bridge_bytes, ffi, AesCbc, CryptoKitError, Result, SymmetricKey};

    fn raw_decrypt(ciphertext: &[u8], key: &SymmetricKey, iv: &[u8]) -> Result<Vec<u8>> {
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

    #[test]
    fn swift_bridge_reports_one_decryption_error() -> Result<()> {
        let key = SymmetricKey::from_bytes(vec![0x11; 16]);
        let iv = [0x22_u8; 16];
        let ciphertext = AesCbc::encrypt_pkcs7(b"hello", &key, &iv)?;

        let expected = CryptoKitError::DecryptionFailed("AES-CBC decryption failed".to_owned());
        assert_eq!(raw_decrypt(&ciphertext[..15], &key, &iv), Err(expected.clone()));
        assert_eq!(raw_decrypt(&[], &key, &iv), Err(expected.clone()));
        for pad in [0x00_u8, 0x02, 0x11, 0xff] {
            let mut tampered_iv = iv;
            tampered_iv[15] ^= 0x0b ^ pad;
            if let Err(error) = raw_decrypt(&ciphertext, &key, &tampered_iv) {
                assert_eq!(error, expected);
            }
        }
        assert_eq!(raw_decrypt(&ciphertext, &key, &iv)?, b"hello");
        Ok(())
    }
}
