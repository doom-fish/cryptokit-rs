use cryptokit::key_agreement::{self, KeyAgreementAlgorithm, KeyAgreementPrivateKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algorithms = key_agreement::supported_algorithms();
    assert!(algorithms.contains(&KeyAgreementAlgorithm::X25519));

    let alice = KeyAgreementPrivateKey::generate(KeyAgreementAlgorithm::X25519)?;
    let bob = KeyAgreementPrivateKey::generate(KeyAgreementAlgorithm::X25519)?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    println!("generic key-agreement algorithms: {}", algorithms.len());
    Ok(())
}
