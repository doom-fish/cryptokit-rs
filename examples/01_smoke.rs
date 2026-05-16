use std::fmt::Write as _;

use cryptokit::prelude::*;

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let digest = sha256(b"hello")?;
    assert_eq!(
        hex(&digest),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );

    let key = SymmetricKey::generate(SymmetricKeySize::Bits256)?;
    let message = vec![0x41_u8; 1024];
    let sealed = AesGcm::seal(&message, &key, None)?;
    let opened = AesGcm::open(&sealed, &key)?;
    assert_eq!(opened, message);

    let signing = SigningPrivateKey::generate(SigningAlgorithm::Ed25519)?;
    let public = signing.public_key()?;
    let signature = signing.sign(b"doom fish cryptokit smoke")?;
    assert!(public.verify(b"doom fish cryptokit smoke", &signature)?);

    let alice = KeyAgreementPrivateKey::generate(KeyAgreementAlgorithm::P256)?;
    let bob = KeyAgreementPrivateKey::generate(KeyAgreementAlgorithm::P256)?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    let derived = alice_secret.hkdf_sha256(b"salt", b"info", 32)?;
    assert_eq!(derived.as_bytes().len(), 32);

    println!("✅ cryptokit hash + AEAD + sig + ECDH OK");
    Ok(())
}
