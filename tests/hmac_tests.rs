mod common;

use cryptokit::hmac::{hmac_sha256_code, is_valid_hmac_sha256, HmacSha256};
use cryptokit::{hmac_sha256, Result, SymmetricKey};

#[test]
fn hmac_sha256_matches_rfc_4231_test_case_1() -> Result<()> {
    let key = SymmetricKey::from_bytes(vec![0x0b; 20]);
    let code = hmac_sha256(b"Hi There", &key)?;
    assert_eq!(
        common::hex(&code),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    Ok(())
}

#[test]
fn typed_and_streaming_hmac_sha256_match_and_verify() -> Result<()> {
    let key = SymmetricKey::from_bytes(vec![0x0b; 20]);
    let typed = hmac_sha256_code(b"Hi There", &key)?;
    assert_eq!(typed.as_bytes(), hmac_sha256(b"Hi There", &key)?.as_slice());
    assert!(is_valid_hmac_sha256(&typed, b"Hi There", &key)?);

    let mut streaming = HmacSha256::new(&key)?;
    streaming.update(b"Hi ")?;
    streaming.update(b"There")?;
    assert_eq!(typed, streaming.finalize()?);
    Ok(())
}
