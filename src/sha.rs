//! SHA-family hashing helpers.

use crate::error::Result;
use crate::ffi;
use crate::private::bridge_bytes;

/// SHA-family algorithms exposed by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ShaAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// Hash input bytes with a SHA-family algorithm.
///
/// # Errors
///
/// Returns an error if the Swift bridge rejects the request.
pub fn digest(algorithm: ShaAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    bridge_bytes(|out, out_len, error_out| unsafe {
        match algorithm {
            ShaAlgorithm::Sha256 => {
                ffi::ck_sha256(data.as_ptr(), data.len(), out, out_len, error_out)
            }
            ShaAlgorithm::Sha384 => {
                ffi::ck_sha384(data.as_ptr(), data.len(), out, out_len, error_out)
            }
            ShaAlgorithm::Sha512 => {
                ffi::ck_sha512(data.as_ptr(), data.len(), out, out_len, error_out)
            }
        }
    })
}

/// Compute a SHA-256 digest.
///
/// # Errors
///
/// Returns an error if hashing fails.
pub fn sha256(data: &[u8]) -> Result<Vec<u8>> {
    digest(ShaAlgorithm::Sha256, data)
}

/// Compute a SHA-384 digest.
///
/// # Errors
///
/// Returns an error if hashing fails.
pub fn sha384(data: &[u8]) -> Result<Vec<u8>> {
    digest(ShaAlgorithm::Sha384, data)
}

/// Compute a SHA-512 digest.
///
/// # Errors
///
/// Returns an error if hashing fails.
pub fn sha512(data: &[u8]) -> Result<Vec<u8>> {
    digest(ShaAlgorithm::Sha512, data)
}
