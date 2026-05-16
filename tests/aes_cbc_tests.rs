use cryptokit::aes_cbc::AesCbc;
use cryptokit::{CryptoKitError, Result, SymmetricKey};

#[test]
fn aes_cbc_pkcs7_round_trips() -> Result<()> {
    let key = SymmetricKey::from_bytes(vec![0x33; 32]);
    let iv = [0x44_u8; 16];
    let ciphertext = AesCbc::encrypt_pkcs7(b"cbc mode plaintext", &key, &iv)?;
    let plaintext = AesCbc::decrypt_pkcs7(&ciphertext, &key, &iv)?;
    assert_eq!(plaintext.as_slice(), b"cbc mode plaintext");
    Ok(())
}

#[test]
fn aes_cbc_rejects_invalid_iv_length() {
    let key = SymmetricKey::from_bytes(vec![0x55; 16]);
    let result = AesCbc::encrypt_pkcs7(b"hello", &key, &[0_u8; 15]);
    assert!(matches!(result, Err(CryptoKitError::InvalidArgument(_))));
}
