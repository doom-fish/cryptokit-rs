use cryptokit::public_key::{
    KeyAgreementAlgorithm, KeyAgreementPrivateKey, KeyAgreementPublicKey, SigningAlgorithm,
    SigningPrivateKey, SigningPublicKey,
};
use cryptokit::Result;

fn main() -> Result<()> {
    let signing =
        SigningPrivateKey::generate_with_compact_representable(SigningAlgorithm::P256, true)?;
    let verifying = signing.public_key()?;

    let signing_der = signing.der_representation()?;
    let verifying_pem = verifying.pem_representation()?;
    let compact = verifying
        .compact_representation()?
        .expect("compact-representable key should expose a compact public key");

    let restored_signing =
        SigningPrivateKey::from_der_representation(SigningAlgorithm::P256, signing_der)?;
    let restored_verifying =
        SigningPublicKey::from_compact_representation(SigningAlgorithm::P256, compact)?;

    assert_eq!(
        restored_signing.raw_representation(),
        signing.raw_representation()
    );
    assert_eq!(
        restored_verifying.raw_representation(),
        verifying.raw_representation()
    );

    let agreement = KeyAgreementPrivateKey::generate_with_compact_representable(
        KeyAgreementAlgorithm::P256,
        true,
    )?;
    let agreement_public = agreement.public_key()?;
    let agreement_x963 = agreement_public.x963_representation()?;
    let restored_agreement_public = KeyAgreementPublicKey::from_x963_representation(
        KeyAgreementAlgorithm::P256,
        agreement_x963,
    )?;
    assert_eq!(
        restored_agreement_public.raw_representation(),
        agreement_public.raw_representation()
    );

    println!("{}", verifying_pem.lines().next().unwrap_or_default());
    println!(
        "agreement-key-bytes={}",
        agreement.raw_representation().len()
    );
    Ok(())
}
