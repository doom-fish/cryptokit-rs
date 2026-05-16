//! HKDF key derivation.

use crate::error::{CryptoKitError, Result};
use crate::ffi;
use crate::private::bridge_bytes;
use crate::symmetric::SymmetricKey;

/// HKDF variants exposed by the Swift bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HkdfAlgorithm {
    Sha256,
    Sha384,
    Sha512,
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

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::{hkdf, hkdf_sha256, HkdfAlgorithm, Result, SymmetricKey};

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
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
