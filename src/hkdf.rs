//! HKDF key derivation.

use crate::error::{CryptoKitError, Result};
use crate::ffi;
use crate::hmac::{HashedAuthenticationCode, HmacHashFunction};
use crate::private::bridge_bytes;
use crate::sha::{Sha256, Sha384, Sha512};
use crate::symmetric::SymmetricKey;

/// HKDF variants exposed by the Swift bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HkdfAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HkdfAlgorithm {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::Sha256 => ffi::hash_algorithm::SHA256,
            Self::Sha384 => ffi::hash_algorithm::SHA384,
            Self::Sha512 => ffi::hash_algorithm::SHA512,
        }
    }
}

/// Hash functions that can back `CryptoKit.HKDF<H>`.
pub trait HkdfHashFunction: HmacHashFunction {
    /// Dynamic algorithm selector used by the FFI bridge.
    const HKDF_ALGORITHM: HkdfAlgorithm;
}

impl HkdfHashFunction for Sha256 {
    const HKDF_ALGORITHM: HkdfAlgorithm = HkdfAlgorithm::Sha256;
}

impl HkdfHashFunction for Sha384 {
    const HKDF_ALGORITHM: HkdfAlgorithm = HkdfAlgorithm::Sha384;
}

impl HkdfHashFunction for Sha512 {
    const HKDF_ALGORITHM: HkdfAlgorithm = HkdfAlgorithm::Sha512;
}

/// Derive a symmetric key with HKDF.
///
/// # Errors
///
/// Returns an error if `output_len` is zero or the Swift bridge rejects the request.
pub fn hkdf(
    algorithm: HkdfAlgorithm,
    input_key_material: &SymmetricKey,
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<SymmetricKey> {
    if output_len == 0 {
        return Err(CryptoKitError::InvalidArgument(
            "HKDF output length must be greater than zero".to_owned(),
        ));
    }

    let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
        match algorithm {
            HkdfAlgorithm::Sha256 => ffi::ck_hkdf_sha256(
                input_key_material.as_bytes().as_ptr(),
                input_key_material.as_bytes().len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                output_len,
                out,
                out_len,
                error_out,
            ),
            HkdfAlgorithm::Sha384 => ffi::ck_hkdf_sha384(
                input_key_material.as_bytes().as_ptr(),
                input_key_material.as_bytes().len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                output_len,
                out,
                out_len,
                error_out,
            ),
            HkdfAlgorithm::Sha512 => ffi::ck_hkdf_sha512(
                input_key_material.as_bytes().as_ptr(),
                input_key_material.as_bytes().len(),
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

/// Extract an HKDF pseudo-random key.
///
/// # Errors
///
/// Returns an error if the Swift bridge rejects the request.
pub fn extract<H>(
    input_key_material: &SymmetricKey,
    salt: Option<&[u8]>,
) -> Result<HashedAuthenticationCode<H>>
where
    H: HkdfHashFunction,
{
    let (salt_ptr, salt_len) = salt.map_or((std::ptr::null(), 0_usize), |salt| {
        (salt.as_ptr(), salt.len())
    });
    let prk = bridge_bytes(|out, out_len, error_out| unsafe {
        ffi::ck_hkdf_extract(
            H::HKDF_ALGORITHM.as_ffi(),
            input_key_material.as_bytes().as_ptr(),
            input_key_material.as_bytes().len(),
            salt_ptr,
            salt_len,
            out,
            out_len,
            error_out,
        )
    })?;
    HashedAuthenticationCode::from_bytes(prk)
}

/// Expand an HKDF pseudo-random key into a symmetric key.
///
/// # Errors
///
/// Returns an error if `output_len` is zero or the Swift bridge rejects the request.
pub fn expand<H>(
    pseudo_random_key: &HashedAuthenticationCode<H>,
    info: Option<&[u8]>,
    output_len: usize,
) -> Result<SymmetricKey>
where
    H: HkdfHashFunction,
{
    if output_len == 0 {
        return Err(CryptoKitError::InvalidArgument(
            "HKDF output length must be greater than zero".to_owned(),
        ));
    }

    let (info_ptr, info_len) = info.map_or((std::ptr::null(), 0_usize), |info| {
        (info.as_ptr(), info.len())
    });
    let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
        ffi::ck_hkdf_expand(
            H::HKDF_ALGORITHM.as_ffi(),
            pseudo_random_key.as_bytes().as_ptr(),
            pseudo_random_key.as_bytes().len(),
            info_ptr,
            info_len,
            output_len,
            out,
            out_len,
            error_out,
        )
    })?;
    Ok(SymmetricKey::from_bytes(bytes))
}

/// Derive a symmetric key with HKDF-SHA256.
///
/// # Errors
///
/// Returns an error if derivation fails.
pub fn hkdf_sha256(
    input_key_material: &SymmetricKey,
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<SymmetricKey> {
    hkdf(
        HkdfAlgorithm::Sha256,
        input_key_material,
        salt,
        info,
        output_len,
    )
}

/// Extract an HKDF-SHA256 pseudo-random key.
///
/// # Errors
///
/// Returns an error if extraction fails.
pub fn hkdf_extract_sha256(
    input_key_material: &SymmetricKey,
    salt: Option<&[u8]>,
) -> Result<HashedAuthenticationCode<Sha256>> {
    extract::<Sha256>(input_key_material, salt)
}

/// Expand an HKDF-SHA256 pseudo-random key.
///
/// # Errors
///
/// Returns an error if expansion fails.
pub fn hkdf_expand_sha256(
    pseudo_random_key: &HashedAuthenticationCode<Sha256>,
    info: Option<&[u8]>,
    output_len: usize,
) -> Result<SymmetricKey> {
    expand::<Sha256>(pseudo_random_key, info, output_len)
}

/// Derive a symmetric key with HKDF-SHA384.
///
/// # Errors
///
/// Returns an error if derivation fails.
pub fn hkdf_sha384(
    input_key_material: &SymmetricKey,
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<SymmetricKey> {
    hkdf(
        HkdfAlgorithm::Sha384,
        input_key_material,
        salt,
        info,
        output_len,
    )
}

/// Extract an HKDF-SHA384 pseudo-random key.
///
/// # Errors
///
/// Returns an error if extraction fails.
pub fn hkdf_extract_sha384(
    input_key_material: &SymmetricKey,
    salt: Option<&[u8]>,
) -> Result<HashedAuthenticationCode<Sha384>> {
    extract::<Sha384>(input_key_material, salt)
}

/// Expand an HKDF-SHA384 pseudo-random key.
///
/// # Errors
///
/// Returns an error if expansion fails.
pub fn hkdf_expand_sha384(
    pseudo_random_key: &HashedAuthenticationCode<Sha384>,
    info: Option<&[u8]>,
    output_len: usize,
) -> Result<SymmetricKey> {
    expand::<Sha384>(pseudo_random_key, info, output_len)
}

/// Derive a symmetric key with HKDF-SHA512.
///
/// # Errors
///
/// Returns an error if derivation fails.
pub fn hkdf_sha512(
    input_key_material: &SymmetricKey,
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<SymmetricKey> {
    hkdf(
        HkdfAlgorithm::Sha512,
        input_key_material,
        salt,
        info,
        output_len,
    )
}

/// Extract an HKDF-SHA512 pseudo-random key.
///
/// # Errors
///
/// Returns an error if extraction fails.
pub fn hkdf_extract_sha512(
    input_key_material: &SymmetricKey,
    salt: Option<&[u8]>,
) -> Result<HashedAuthenticationCode<Sha512>> {
    extract::<Sha512>(input_key_material, salt)
}

/// Expand an HKDF-SHA512 pseudo-random key.
///
/// # Errors
///
/// Returns an error if expansion fails.
pub fn hkdf_expand_sha512(
    pseudo_random_key: &HashedAuthenticationCode<Sha512>,
    info: Option<&[u8]>,
    output_len: usize,
) -> Result<SymmetricKey> {
    expand::<Sha512>(pseudo_random_key, info, output_len)
}

#[cfg(test)]
mod tests {
    use super::{
        hkdf, hkdf_expand_sha256, hkdf_extract_sha256, hkdf_sha256, HkdfAlgorithm, Result,
        SymmetricKey,
    };

    fn hex(bytes: &[u8]) -> String {
        crate::private::hex(bytes)
    }

    #[test]
    fn sha256_matches_rfc_5869_test_case_1() -> Result<()> {
        let input_key_material = SymmetricKey::from_bytes(vec![0x0b; 22]);
        let salt = [
            0x00_u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [
            0xf0_u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
        ];
        let derived = hkdf_sha256(&input_key_material, &salt, &info, 42)?;
        assert_eq!(
            hex(derived.as_bytes()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        Ok(())
    }

    #[test]
    fn sha256_extract_expand_matches_derive() -> Result<()> {
        let input_key_material = SymmetricKey::from_bytes(vec![0x0b; 22]);
        let salt = [
            0x00_u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [
            0xf0_u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
        ];

        let derived = hkdf_sha256(&input_key_material, &salt, &info, 42)?;
        let prk = hkdf_extract_sha256(&input_key_material, Some(&salt))?;
        let expanded = hkdf_expand_sha256(&prk, Some(&info), 42)?;

        assert_eq!(derived.as_bytes(), expanded.as_bytes());
        assert_eq!(prk.byte_count(), 32);
        Ok(())
    }

    #[test]
    fn sha384_and_sha512_return_requested_lengths() -> Result<()> {
        let input_key_material = SymmetricKey::from_bytes(vec![0x42; 32]);
        let salt = [0x24_u8; 16];
        let info = [0x99_u8; 8];

        let sha384 = hkdf(HkdfAlgorithm::Sha384, &input_key_material, &salt, &info, 48)?;
        let sha512 = hkdf(HkdfAlgorithm::Sha512, &input_key_material, &salt, &info, 64)?;
        assert_eq!(sha384.as_bytes().len(), 48);
        assert_eq!(sha512.as_bytes().len(), 64);
        Ok(())
    }
}
