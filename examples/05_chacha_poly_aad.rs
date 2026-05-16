use cryptokit::chacha_poly::ChaChaPoly;
use cryptokit::SymmetricKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = SymmetricKey::from_bytes(vec![0x55; 32]);
    let nonce = [0x66_u8; 12];
    let sealed = ChaChaPoly::seal_with_aad(b"chacha example", &key, Some(&nonce), b"aad")?;
    let opened = ChaChaPoly::open_with_aad(&sealed, &key, b"aad")?;
    assert_eq!(opened.as_slice(), b"chacha example");
    println!(
        "chacha-poly ciphertext bytes: {}",
        sealed.ciphertext().len()
    );
    Ok(())
}
