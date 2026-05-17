use cryptokit::p256::{
    self, P256KeyAgreementPrivateKey, P256KeyAgreementPublicKey, P256SigningPrivateKey,
    P256SigningPublicKey,
};
use cryptokit::Result;

#[test]
fn p256_signing_and_key_agreement_round_trip() -> Result<()> {
    assert!(p256::is_supported());

    let signing = P256SigningPrivateKey::generate()?;
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"p256 message")?;
    assert!(verifying.verify(b"p256 message", &signature)?);

    let typed_signature = signing.sign_signature(b"typed p256 message")?;
    assert!(verifying.verify_signature(b"typed p256 message", &typed_signature)?);
    let der_signature = typed_signature.der_representation()?;
    let typed_roundtrip = p256::P256EcdsaSignature::from_der_representation(der_signature)?;
    assert!(verifying.verify_signature(b"typed p256 message", &typed_roundtrip)?);

    let representable_signing = P256SigningPrivateKey::generate_with_compact_representable(true)?;
    let representable_public = representable_signing.public_key()?;
    let signing_pem = representable_signing.pem_representation()?;
    assert_eq!(
        P256SigningPrivateKey::from_pem_representation(signing_pem)?.raw_representation(),
        representable_signing.raw_representation()
    );
    let compact = representable_public
        .compact_representation()?
        .expect("compact-representable key should expose a compact public key");
    assert_eq!(
        P256SigningPublicKey::from_compact_representation(compact)?.raw_representation(),
        representable_public.raw_representation()
    );

    let alice = P256KeyAgreementPrivateKey::generate()?;
    let bob = P256KeyAgreementPrivateKey::generate()?;
    let alice_secret = alice.shared_secret(&bob.public_key()?)?;
    let bob_secret = bob.shared_secret(&alice.public_key()?)?;
    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());

    let representable_agreement = P256KeyAgreementPrivateKey::generate_with_compact_representable(true)?;
    let representable_agreement_public = representable_agreement.public_key()?;
    let x963 = representable_agreement_public.x963_representation()?;
    assert_eq!(
        P256KeyAgreementPublicKey::from_x963_representation(x963)?.raw_representation(),
        representable_agreement_public.raw_representation()
    );
    Ok(())
}
