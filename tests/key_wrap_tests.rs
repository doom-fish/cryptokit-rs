use cryptokit::key_wrap::AesKeyWrap;
use cryptokit::{Result, SymmetricKey};

#[test]
fn aes_key_wrap_round_trips() -> Result<()> {
    let key_to_wrap = SymmetricKey::from_bytes(vec![0x11; 32]);
    let kek = SymmetricKey::from_bytes(vec![0x22; 32]);

    let wrapped = AesKeyWrap::wrap(&key_to_wrap, &kek)?;
    assert_ne!(wrapped, key_to_wrap.as_bytes());

    let unwrapped = AesKeyWrap::unwrap(&wrapped, &kek)?;
    assert_eq!(unwrapped, key_to_wrap);
    Ok(())
}
