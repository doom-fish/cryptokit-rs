use cryptokit::p521::{self, P521KeyAgreementPrivateKey, P521SigningPrivateKey};
use cryptokit::Result;

#[test]
fn p521_signing_and_key_agreement_round_trip() -> Result<()> {
    assert!(p521::is_supported());

    let signing = P521SigningPrivateKey::generate()?;
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"p521 message")?;
    assert!(verifying.verify(b"p521 message", &signature)?);

    let typed_signature = signing.sign_signature(b"typed p521 message")?;
    assert!(verifying.verify_signature(b"typed p521 message", &typed_signature)?);
    let der_signature = typed_signature.der_representation()?;
    let typed_roundtrip = p521::P521EcdsaSignature::from_der_representation(der_signature)?;
    assert!(verifying.verify_signature(b"typed p521 message", &typed_roundtrip)?);

    let alice = P521KeyAgreementPrivateKey::generate()?;
    let bob = P521KeyAgreementPrivateKey::generate()?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    Ok(())
}
