use cryptokit::aes_cbc::AesCbc;
use cryptokit::SymmetricKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = SymmetricKey::from_bytes(vec![0x33; 32]);
    let iv = [0x44_u8; 16];
    let ciphertext = AesCbc::encrypt_pkcs7(b"aes-cbc example", &key, &iv)?;
    let plaintext = AesCbc::decrypt_pkcs7(&ciphertext, &key, &iv)?;
    assert_eq!(plaintext.as_slice(), b"aes-cbc example");
    println!("aes-cbc ciphertext bytes: {}", ciphertext.len());
    Ok(())
}
