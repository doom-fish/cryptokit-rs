use cryptokit::p521::{P521KeyAgreementPrivateKey, P521SigningPrivateKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing = P521SigningPrivateKey::generate()?;
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"p521 example")?;
    assert!(verifying.verify(b"p521 example", &signature)?);

    let alice = P521KeyAgreementPrivateKey::generate()?;
    let bob = P521KeyAgreementPrivateKey::generate()?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    println!("p521 signature bytes: {}", signature.len());
    Ok(())
}
