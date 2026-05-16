use cryptokit::p256::{self, P256KeyAgreementPrivateKey, P256SigningPrivateKey};
use cryptokit::Result;

#[test]
fn p256_signing_and_key_agreement_round_trip() -> Result<()> {
    assert!(p256::is_supported());

    let signing = P256SigningPrivateKey::generate()?;
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"p256 message")?;
    assert!(verifying.verify(b"p256 message", &signature)?);

    let alice = P256KeyAgreementPrivateKey::generate()?;
    let bob = P256KeyAgreementPrivateKey::generate()?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    Ok(())
}
