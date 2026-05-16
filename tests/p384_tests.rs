use cryptokit::p384::{self, P384KeyAgreementPrivateKey, P384SigningPrivateKey};
use cryptokit::Result;

#[test]
fn p384_signing_and_key_agreement_round_trip() -> Result<()> {
    assert!(p384::is_supported());

    let signing = P384SigningPrivateKey::generate()?;
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"p384 message")?;
    assert!(verifying.verify(b"p384 message", &signature)?);

    let alice = P384KeyAgreementPrivateKey::generate()?;
    let bob = P384KeyAgreementPrivateKey::generate()?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    Ok(())
}
