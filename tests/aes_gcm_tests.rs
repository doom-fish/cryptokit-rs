use cryptokit::aes_gcm::{AesGcm, AesGcmSealedBox};
use cryptokit::{Result, SymmetricKey};

#[test]
fn aes_gcm_round_trips_with_authenticated_data() -> Result<()> {
    let key = SymmetricKey::from_bytes(vec![0x11; 32]);
    let nonce = [0x22_u8; 12];
    let sealed = AesGcm::seal_with_aad(b"aes-gcm test", &key, Some(&nonce), b"aad")?;
    assert_eq!(sealed.nonce(), nonce);
    assert_eq!(sealed.tag().len(), 16);
    let reopened = AesGcm::open_with_aad(&sealed, &key, b"aad")?;
    assert_eq!(reopened.as_slice(), b"aes-gcm test");

    let reparsed = AesGcmSealedBox::from_combined(sealed.combined().to_vec())?;
    assert_eq!(reparsed.ciphertext(), sealed.ciphertext());
    Ok(())
}

#[test]
fn typed_nonce_and_sealed_box_parts_round_trip() -> Result<()> {
    let key = SymmetricKey::from_bytes(vec![0x33; 32]);
    let nonce = cryptokit::aes_gcm::AesGcmNonce::from_bytes([0x44_u8; 12])?;
    let sealed = AesGcm::seal_with_nonce_and_aad(b"typed nonce", &key, &nonce, b"aad")?;

    assert_eq!(sealed.nonce_value()?, nonce);
    assert_eq!(
        cryptokit::aes_gcm::AesGcmNonce::generate()?
            .as_bytes()
            .len(),
        12
    );

    let rebuilt = AesGcmSealedBox::from_parts(&nonce, sealed.ciphertext(), sealed.tag())?;
    assert_eq!(rebuilt.combined(), sealed.combined());
    Ok(())
}
