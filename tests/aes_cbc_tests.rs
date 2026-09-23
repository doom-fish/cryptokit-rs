use cryptokit::hazmat::aes_cbc::AesCbc;
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

#[test]
fn aes_cbc_decryption_failures_are_indistinguishable() -> Result<()> {
    let key = SymmetricKey::from_bytes(vec![0x11; 32]);
    let iv = [0x22_u8; 16];
    let ciphertext = AesCbc::encrypt_pkcs7(b"hello", &key, &iv)?;
    assert_eq!(ciphertext.len(), 16);

    let Err(length_error) = AesCbc::decrypt_pkcs7(&ciphertext[..15], &key, &iv) else {
        panic!("truncated ciphertext must not decrypt");
    };
    let Err(empty_error) = AesCbc::decrypt_pkcs7(&[], &key, &iv) else {
        panic!("empty ciphertext must not decrypt");
    };
    assert!(matches!(length_error, CryptoKitError::DecryptionFailed(_)));
    assert_eq!(length_error, empty_error);
    assert_eq!(length_error.message(), "AES-CBC decryption failed");

    for pad in [0x00_u8, 0x02, 0x11, 0xff] {
        let mut tampered_iv = iv;
        tampered_iv[15] ^= 0x0b ^ pad;
        if let Err(padding_error) = AesCbc::decrypt_pkcs7(&ciphertext, &key, &tampered_iv) {
            assert_eq!(padding_error, length_error);
        }
    }
    Ok(())
}
