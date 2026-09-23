mod common;

use cryptokit::hkdf::hkdf_extract_sha256;
use cryptokit::hmac::{is_valid_hmac_sha256, HmacSha256};
use cryptokit::{hmac_sha256, Result, SymmetricKey};

#[test]
fn hmac_sha256_matches_rfc_4231_test_case_1() -> Result<()> {
    let key = SymmetricKey::from_bytes(vec![0x0b; 20]);
    let code = hmac_sha256(b"Hi There", &key)?;
    assert_eq!(
        common::hex(code.as_bytes()),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    Ok(())
}

#[test]
fn typed_and_streaming_hmac_sha256_match_and_verify() -> Result<()> {
    let key = SymmetricKey::from_bytes(vec![0x0b; 20]);
    let typed = hmac_sha256(b"Hi There", &key)?;
    assert!(is_valid_hmac_sha256(&typed, b"Hi There", &key)?);
    assert!(!is_valid_hmac_sha256(&typed, b"Hi there", &key)?);

    let mut streaming = HmacSha256::new(&key)?;
    streaming.update(b"Hi ")?;
    streaming.update(b"There")?;
    assert_eq!(typed, streaming.finalize()?);
    Ok(())
}

#[test]
fn authentication_codes_compare_against_received_bytes() -> Result<()> {
    let key = SymmetricKey::from_bytes(vec![0x0b; 20]);
    let computed = hmac_sha256(b"Hi There", &key)?;
    let received = computed.as_bytes().to_vec();
    let mut array = [0_u8; 32];
    array.copy_from_slice(&received);

    assert_eq!(computed, received);
    assert_eq!(computed, received.as_slice());
    assert_eq!(computed, *received.as_slice());
    assert_eq!(computed, array);

    let mut tampered = received.clone();
    tampered[31] ^= 0x01;
    assert_ne!(computed, tampered);
    assert_ne!(computed, received[..31].to_vec());
    assert_ne!(computed, hmac_sha256(b"Hi There!", &key)?);
    Ok(())
}

#[test]
fn authentication_codes_and_prks_redact_debug() -> Result<()> {
    let key = SymmetricKey::from_bytes(vec![0x0b; 20]);
    let computed = hmac_sha256(b"Hi There", &key)?;
    assert_eq!(
        format!("{computed:?}"),
        "HashedAuthenticationCode { byte_count: 32, .. }"
    );
    assert_eq!(computed.to_string(), common::hex(computed.as_bytes()));

    let prk = hkdf_extract_sha256(&key, Some(b"salt"))?;
    assert_eq!(
        format!("{prk:?}"),
        "HashedAuthenticationCode { byte_count: 32, .. }"
    );
    Ok(())
}
