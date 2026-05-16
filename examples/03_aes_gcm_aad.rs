use cryptokit::aes_gcm::AesGcm;
use cryptokit::SymmetricKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = SymmetricKey::from_bytes(vec![0x11; 32]);
    let nonce = [0x22_u8; 12];
    let sealed = AesGcm::seal_with_aad(b"aes-gcm example", &key, Some(&nonce), b"aad")?;
    let opened = AesGcm::open_with_aad(&sealed, &key, b"aad")?;
    assert_eq!(opened.as_slice(), b"aes-gcm example");
    println!("aes-gcm ciphertext bytes: {}", sealed.ciphertext().len());
    Ok(())
}
