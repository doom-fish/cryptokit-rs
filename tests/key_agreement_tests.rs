use cryptokit::key_agreement::{self, KeyAgreementAlgorithm, KeyAgreementPrivateKey};
use cryptokit::Result;

#[test]
fn supported_algorithms_include_all_expected_variants() {
    let algorithms = key_agreement::supported_algorithms();
    assert!(algorithms.contains(&KeyAgreementAlgorithm::P256));
    assert!(algorithms.contains(&KeyAgreementAlgorithm::P384));
    assert!(algorithms.contains(&KeyAgreementAlgorithm::P521));
    assert!(algorithms.contains(&KeyAgreementAlgorithm::X25519));
}

#[test]
fn generic_key_agreement_round_trips() -> Result<()> {
    let alice = KeyAgreementPrivateKey::generate(KeyAgreementAlgorithm::X25519)?;
    let bob = KeyAgreementPrivateKey::generate(KeyAgreementAlgorithm::X25519)?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    Ok(())
}
