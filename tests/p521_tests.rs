use cryptokit::p521::{self, P521KeyAgreementPrivateKey, P521SigningPrivateKey};
use cryptokit::Result;

#[test]
fn p521_signing_and_key_agreement_round_trip() -> Result<()> {
    assert!(p521::is_supported());

    let signing = P521SigningPrivateKey::generate()?;
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"p521 message")?;
    assert!(verifying.verify(b"p521 message", &signature)?);

    let alice = P521KeyAgreementPrivateKey::generate()?;
    let bob = P521KeyAgreementPrivateKey::generate()?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    Ok(())
}
