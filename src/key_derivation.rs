//! Shared-secret key-derivation helpers.

use crate::error::{CryptoKitError, Result};
use crate::ffi;
use crate::hkdf::{validate_output_byte_count, HkdfAlgorithm};
use crate::private::bridge_bytes;
use crate::public_key::SharedSecret;
use crate::sha::ShaAlgorithm;
use crate::symmetric::SymmetricKey;

const X963_MAX_COUNTER: usize = 4_294_967_295;

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
    validate_output_byte_count(algorithm, output_len)?;
    let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
        ffi::ck_shared_secret_hkdf(
            secret.handle.as_ptr(),
            algorithm.as_ffi(),
            salt.as_ptr(),
            salt.len(),
            info.as_ptr(),
            info.len(),
            output_len,
            out,
            out_len,
            error_out,
        )
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
    let limit = algorithm
        .digest_byte_count()
        .saturating_mul(X963_MAX_COUNTER);
    if output_len == 0 || output_len >= limit {
        return Err(CryptoKitError::InvalidArgument(format!(
            "ANSI X9.63 output length must be between 1 and {} bytes, got {output_len}",
            limit - 1
        )));
    }

    let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
        ffi::ck_shared_secret_x963(
            secret.handle.as_ptr(),
            algorithm.as_ffi(),
            shared_info.as_ptr(),
            shared_info.len(),
            output_len,
            out,
            out_len,
            error_out,
        )
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

#[cfg(test)]
mod tests {
    use std::ptr;

    use super::{derive_x963, CryptoKitError, Result, ShaAlgorithm};
    use crate::ffi;
    use crate::private::bridge_bytes;
    use crate::public_key::{KeyAgreementAlgorithm, KeyAgreementPrivateKey};

    #[test]
    fn swift_bridge_rejects_unrepresentable_output_lengths() -> Result<()> {
        let alice = KeyAgreementPrivateKey::generate(KeyAgreementAlgorithm::X25519)?;
        let bob = KeyAgreementPrivateKey::generate(KeyAgreementAlgorithm::X25519)?;
        let secret = alice.shared_secret(&bob.public_key()?)?;

        let hkdf = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_shared_secret_hkdf(
                secret.handle.as_ptr(),
                ffi::hash_algorithm::SHA256,
                ptr::null(),
                0,
                ptr::null(),
                0,
                usize::MAX,
                out,
                out_len,
                error_out,
            )
        });
        assert!(matches!(hkdf, Err(CryptoKitError::InvalidArgument(_))));

        let x963 = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_shared_secret_x963(
                secret.handle.as_ptr(),
                ffi::hash_algorithm::SHA384,
                ptr::null(),
                0,
                usize::MAX,
                out,
                out_len,
                error_out,
            )
        });
        assert!(matches!(x963, Err(CryptoKitError::InvalidArgument(_))));

        let oversized_hkdf = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_shared_secret_hkdf(
                secret.handle.as_ptr(),
                ffi::hash_algorithm::SHA256,
                ptr::null(),
                0,
                ptr::null(),
                0,
                255 * 32 + 1,
                out,
                out_len,
                error_out,
            )
        });
        assert!(matches!(oversized_hkdf, Err(CryptoKitError::InvalidArgument(_))));

        assert_eq!(
            derive_x963(&secret, ShaAlgorithm::Sha384, b"info", 49)?
                .as_bytes()
                .len(),
            49
        );
        Ok(())
    }
}
