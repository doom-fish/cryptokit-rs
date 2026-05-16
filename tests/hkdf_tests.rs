mod common;

use cryptokit::hkdf::{hkdf, hkdf_sha256, HkdfAlgorithm};
use cryptokit::{Result, SymmetricKey};

#[test]
fn hkdf_sha256_matches_rfc_5869_test_case_1() -> Result<()> {
    let input_key_material = SymmetricKey::from_bytes(vec![0x0b; 22]);
    let salt = [
        0x00_u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info = [
        0xf0_u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    ];
    let derived = hkdf_sha256(&input_key_material, &salt, &info, 42)?;
    assert_eq!(
        common::hex(derived.as_bytes()),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    Ok(())
}

#[test]
fn hkdf_sha384_and_sha512_return_requested_lengths() -> Result<()> {
    let input_key_material = SymmetricKey::from_bytes(vec![0x88; 32]);
    let sha384 = hkdf(
        HkdfAlgorithm::Sha384,
        &input_key_material,
        b"salt",
        b"info",
        48,
    )?;
    let sha512 = hkdf(
        HkdfAlgorithm::Sha512,
        &input_key_material,
        b"salt",
        b"info",
        64,
    )?;
    assert_eq!(sha384.as_bytes().len(), 48);
    assert_eq!(sha512.as_bytes().len(), 64);
    Ok(())
}
