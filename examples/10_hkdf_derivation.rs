use cryptokit::{hkdf_sha384, hkdf_sha512, SymmetricKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ikm = SymmetricKey::from_bytes(vec![0x88; 32]);
    let sha384 = hkdf_sha384(&ikm, b"salt", b"info", 48)?;
    let sha512 = hkdf_sha512(&ikm, b"salt", b"info", 64)?;
    assert_eq!(sha384.as_bytes().len(), 48);
    assert_eq!(sha512.as_bytes().len(), 64);
    println!(
        "hkdf lengths: {}, {}",
        sha384.as_bytes().len(),
        sha512.as_bytes().len()
    );
    Ok(())
}
