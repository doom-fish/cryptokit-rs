//! Legacy compatibility hashes from `CryptoKit.Insecure`.

use crate::error::Result;
use crate::ffi;
use crate::private::bridge_bytes;

/// Legacy hash algorithms exposed by `CryptoKit.Insecure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InsecureHashAlgorithm {
    Md5,
    Sha1,
}

/// Hash input bytes with a legacy compatibility algorithm.
///
/// # Errors
///
/// Returns an error if the Swift bridge rejects the request.
pub fn hash(algorithm: InsecureHashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    bridge_bytes(|out, out_len, error_out| unsafe {
        match algorithm {
            InsecureHashAlgorithm::Md5 => {
                ffi::ck_md5(data.as_ptr(), data.len(), out, out_len, error_out)
            }
            InsecureHashAlgorithm::Sha1 => {
                ffi::ck_sha1(data.as_ptr(), data.len(), out, out_len, error_out)
            }
        }
    })
}

/// Compute an MD5 digest.
///
/// # Errors
///
/// Returns an error if hashing fails.
pub fn md5(data: &[u8]) -> Result<Vec<u8>> {
    hash(InsecureHashAlgorithm::Md5, data)
}

/// Compute a SHA-1 digest.
///
/// # Errors
///
/// Returns an error if hashing fails.
pub fn sha1(data: &[u8]) -> Result<Vec<u8>> {
    hash(InsecureHashAlgorithm::Sha1, data)
}
