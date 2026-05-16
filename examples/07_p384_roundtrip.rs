use cryptokit::p384::{P384KeyAgreementPrivateKey, P384SigningPrivateKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing = P384SigningPrivateKey::generate()?;
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"p384 example")?;
    assert!(verifying.verify(b"p384 example", &signature)?);

    let alice = P384KeyAgreementPrivateKey::generate()?;
    let bob = P384KeyAgreementPrivateKey::generate()?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    println!("p384 signature bytes: {}", signature.len());
    Ok(())
}
