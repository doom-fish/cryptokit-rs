//! Cryptographic and legacy hash functions.

use crate::error::Result;
use crate::ffi;
use crate::private::bridge_bytes;

/// Hash algorithms exposed by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Md5,
    Sha1,
}

impl HashAlgorithm {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::Sha256 => ffi::hash_algorithm::SHA256,
            Self::Sha384 => ffi::hash_algorithm::SHA384,
            Self::Sha512 => ffi::hash_algorithm::SHA512,
            Self::Md5 => ffi::hash_algorithm::MD5,
            Self::Sha1 => ffi::hash_algorithm::SHA1,
        }
    }
}

/// Hash input bytes with the selected algorithm.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    bridge_bytes(|out, out_len, error_out| unsafe {
        ffi::ck_hash(
            algorithm.as_ffi(),
            data.as_ptr(),
            data.len(),
            out,
            out_len,
            error_out,
        )
    })
}

/// Compute a SHA-256 digest.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn sha256(data: &[u8]) -> Result<Vec<u8>> {
    hash(HashAlgorithm::Sha256, data)
}

/// Compute a SHA-384 digest.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn sha384(data: &[u8]) -> Result<Vec<u8>> {
    hash(HashAlgorithm::Sha384, data)
}

/// Compute a SHA-512 digest.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn sha512(data: &[u8]) -> Result<Vec<u8>> {
    hash(HashAlgorithm::Sha512, data)
}

/// Compute an MD5 digest via `CryptoKit.Insecure.MD5`.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn md5(data: &[u8]) -> Result<Vec<u8>> {
    hash(HashAlgorithm::Md5, data)
}

/// Compute a SHA-1 digest via `CryptoKit.Insecure.SHA1`.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn sha1(data: &[u8]) -> Result<Vec<u8>> {
    hash(HashAlgorithm::Sha1, data)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::{md5, sha1, sha256, Result};

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }

    #[test]
    fn compatibility_hashes_match_known_vectors() -> Result<()> {
        assert_eq!(
            hex(&sha256(b"hello")?),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(hex(&md5(b"hello")?), "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(
            hex(&sha1(b"hello")?),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
        Ok(())
    }
}
