mod common;

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
