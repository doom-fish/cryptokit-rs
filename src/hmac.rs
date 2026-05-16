//! Hash-based message authentication codes.

use crate::error::Result;
use crate::ffi;
use crate::private::bridge_bytes;
use crate::symmetric::SymmetricKey;

/// HMAC algorithms exposed by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HmacAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HmacAlgorithm {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::Sha256 => ffi::hmac_algorithm::SHA256,
            Self::Sha384 => ffi::hmac_algorithm::SHA384,
            Self::Sha512 => ffi::hmac_algorithm::SHA512,
        }
    }
}

/// Compute an HMAC for the given message and symmetric key.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hmac(algorithm: HmacAlgorithm, key: &SymmetricKey, message: &[u8]) -> Result<Vec<u8>> {
    bridge_bytes(|out, out_len, error_out| unsafe {
        ffi::ck_hmac(
            algorithm.as_ffi(),
            key.as_bytes().as_ptr(),
            key.as_bytes().len(),
            message.as_ptr(),
            message.len(),
            out,
            out_len,
            error_out,
        )
    })
}

/// Compute an HMAC-SHA256 authentication code.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hmac_sha256(message: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
    hmac(HmacAlgorithm::Sha256, key, message)
}

/// Compute an HMAC-SHA384 authentication code.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hmac_sha384(message: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
    hmac(HmacAlgorithm::Sha384, key, message)
}

/// Compute an HMAC-SHA512 authentication code.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hmac_sha512(message: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
    hmac(HmacAlgorithm::Sha512, key, message)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::{hmac_sha256, Result, SymmetricKey};

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }

    #[test]
    fn sha256_matches_rfc_4231_test_case_1() -> Result<()> {
        let key = SymmetricKey::from_bytes(vec![0x0b; 20]);
        let code = hmac_sha256(b"Hi There", &key)?;
        assert_eq!(
            hex(&code),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        Ok(())
    }
}
