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
