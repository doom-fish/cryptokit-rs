use cryptokit::curve25519::{self, Ed25519PrivateKey, X25519PrivateKey};
use cryptokit::Result;

#[test]
fn curve25519_signing_and_key_agreement_round_trip() -> Result<()> {
    assert!(curve25519::is_supported());

    let signing = Ed25519PrivateKey::generate()?;
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"curve25519 message")?;
    assert!(verifying.verify(b"curve25519 message", &signature)?);

    let alice = X25519PrivateKey::generate()?;
    let bob = X25519PrivateKey::generate()?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    Ok(())
}
