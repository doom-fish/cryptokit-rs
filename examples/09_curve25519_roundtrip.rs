use cryptokit::curve25519::{Ed25519PrivateKey, X25519PrivateKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing = Ed25519PrivateKey::generate()?;
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"curve25519 example")?;
    assert!(verifying.verify(b"curve25519 example", &signature)?);

    let alice = X25519PrivateKey::generate()?;
    let bob = X25519PrivateKey::generate()?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    println!("ed25519 signature bytes: {}", signature.len());
    Ok(())
}
