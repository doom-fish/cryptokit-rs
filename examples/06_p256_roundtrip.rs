use cryptokit::p256::{P256KeyAgreementPrivateKey, P256SigningPrivateKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing = P256SigningPrivateKey::generate()?;
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"p256 example")?;
    assert!(verifying.verify(b"p256 example", &signature)?);

    let alice = P256KeyAgreementPrivateKey::generate()?;
    let bob = P256KeyAgreementPrivateKey::generate()?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    println!("p256 signature bytes: {}", signature.len());
    Ok(())
}
