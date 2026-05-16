//! Shared-secret key-derivation helpers.

use crate::error::{CryptoKitError, Result};
use crate::ffi;
use crate::hkdf::HkdfAlgorithm;
use crate::private::bridge_bytes;
use crate::public_key::SharedSecret;
use crate::sha::ShaAlgorithm;
use crate::symmetric::SymmetricKey;

/// Key-derivation algorithms supported for shared secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyDerivationAlgorithm {
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
    X963Sha256,
    X963Sha384,
    X963Sha512,
}

/// Derive a symmetric key from a shared secret with HKDF.
///
/// # Errors
///
/// Returns an error if `output_len` is zero or derivation fails.
pub fn derive_hkdf(
    secret: &SharedSecret,
    algorithm: HkdfAlgorithm,
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<SymmetricKey> {
    if output_len == 0 {
        return Err(CryptoKitError::InvalidArgument(
            "derived key length must be greater than zero".to_owned(),
        ));
    }

    let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
        match algorithm {
            HkdfAlgorithm::Sha256 => ffi::ck_shared_secret_hkdf_sha256(
                secret.as_bytes().as_ptr(),
                secret.as_bytes().len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                output_len,
                out,
                out_len,
                error_out,
            ),
            HkdfAlgorithm::Sha384 => ffi::ck_shared_secret_hkdf_sha384(
                secret.as_bytes().as_ptr(),
                secret.as_bytes().len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                output_len,
                out,
                out_len,
                error_out,
            ),
            HkdfAlgorithm::Sha512 => ffi::ck_shared_secret_hkdf_sha512(
                secret.as_bytes().as_ptr(),
                secret.as_bytes().len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                output_len,
                out,
                out_len,
                error_out,
            ),
        }
    })?;
    Ok(SymmetricKey::from_bytes(bytes))
}

/// Derive a symmetric key from a shared secret with ANSI X9.63 KDF.
///
/// # Errors
///
/// Returns an error if `output_len` is zero or derivation fails.
pub fn derive_x963(
    secret: &SharedSecret,
    algorithm: ShaAlgorithm,
    shared_info: &[u8],
    output_len: usize,
) -> Result<SymmetricKey> {
    if output_len == 0 {
        return Err(CryptoKitError::InvalidArgument(
            "derived key length must be greater than zero".to_owned(),
        ));
    }

    let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
        match algorithm {
            ShaAlgorithm::Sha256 => ffi::ck_shared_secret_x963_sha256(
                secret.as_bytes().as_ptr(),
                secret.as_bytes().len(),
                shared_info.as_ptr(),
                shared_info.len(),
                output_len,
                out,
                out_len,
                error_out,
            ),
            ShaAlgorithm::Sha384 => ffi::ck_shared_secret_x963_sha384(
                secret.as_bytes().as_ptr(),
                secret.as_bytes().len(),
                shared_info.as_ptr(),
                shared_info.len(),
                output_len,
                out,
                out_len,
                error_out,
            ),
            ShaAlgorithm::Sha512 => ffi::ck_shared_secret_x963_sha512(
                secret.as_bytes().as_ptr(),
                secret.as_bytes().len(),
                shared_info.as_ptr(),
                shared_info.len(),
                output_len,
                out,
                out_len,
                error_out,
            ),
        }
    })?;
    Ok(SymmetricKey::from_bytes(bytes))
}

/// Derive a symmetric key from a shared secret with the selected algorithm.
///
/// # Errors
///
/// Returns an error if the algorithm/output combination is invalid.
pub fn derive(
    secret: &SharedSecret,
    algorithm: KeyDerivationAlgorithm,
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<SymmetricKey> {
    match algorithm {
        KeyDerivationAlgorithm::HkdfSha256 => {
            derive_hkdf(secret, HkdfAlgorithm::Sha256, salt, info, output_len)
        }
        KeyDerivationAlgorithm::HkdfSha384 => {
            derive_hkdf(secret, HkdfAlgorithm::Sha384, salt, info, output_len)
        }
        KeyDerivationAlgorithm::HkdfSha512 => {
            derive_hkdf(secret, HkdfAlgorithm::Sha512, salt, info, output_len)
        }
        KeyDerivationAlgorithm::X963Sha256 => {
            ensure_no_salt(salt)?;
            derive_x963(secret, ShaAlgorithm::Sha256, info, output_len)
        }
        KeyDerivationAlgorithm::X963Sha384 => {
            ensure_no_salt(salt)?;
            derive_x963(secret, ShaAlgorithm::Sha384, info, output_len)
        }
        KeyDerivationAlgorithm::X963Sha512 => {
            ensure_no_salt(salt)?;
            derive_x963(secret, ShaAlgorithm::Sha512, info, output_len)
        }
    }
}

fn ensure_no_salt(salt: &[u8]) -> Result<()> {
    if salt.is_empty() {
        Ok(())
    } else {
        Err(CryptoKitError::InvalidArgument(
            "X9.63 derivation does not use salt; pass an empty slice".to_owned(),
        ))
    }
}
