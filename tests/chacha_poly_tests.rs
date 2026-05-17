use cryptokit::chacha_poly::{ChaChaPoly, ChaChaPolySealedBox};
use cryptokit::{Result, SymmetricKey};

#[test]
fn chacha_poly_round_trips_with_authenticated_data() -> Result<()> {
    let key = SymmetricKey::from_bytes(vec![0x66; 32]);
    let nonce = [0x77_u8; 12];
    let sealed = ChaChaPoly::seal_with_aad(b"chacha poly test", &key, Some(&nonce), b"aad")?;
    assert_eq!(sealed.nonce(), nonce);
    assert_eq!(sealed.tag().len(), 16);
    let reopened = ChaChaPoly::open_with_aad(&sealed, &key, b"aad")?;
    assert_eq!(reopened.as_slice(), b"chacha poly test");

    let reparsed = ChaChaPolySealedBox::from_combined(sealed.combined().to_vec())?;
    assert_eq!(reparsed.ciphertext(), sealed.ciphertext());
    Ok(())
}

#[test]
fn typed_nonce_and_sealed_box_parts_round_trip() -> Result<()> {
    let key = SymmetricKey::from_bytes(vec![0x88; 32]);
    let nonce = cryptokit::chacha_poly::ChaChaPolyNonce::from_bytes([0x99_u8; 12])?;
    let sealed = ChaChaPoly::seal_with_nonce_and_aad(b"typed nonce", &key, &nonce, b"aad")?;

    assert_eq!(sealed.nonce_value()?, nonce);
    assert_eq!(cryptokit::chacha_poly::ChaChaPolyNonce::generate()?.as_bytes().len(), 12);

    let rebuilt = ChaChaPolySealedBox::from_parts(&nonce, sealed.ciphertext(), sealed.tag())?;
    assert_eq!(rebuilt.combined(), sealed.combined());
    Ok(())
}
