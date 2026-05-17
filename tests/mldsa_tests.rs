use cryptokit::mldsa::{Mldsa65PrivateKey, Mldsa87PrivateKey};
use cryptokit::Result;

#[test]
fn post_quantum_signatures_round_trip() -> Result<()> {
    let mldsa65 = Mldsa65PrivateKey::generate()?;
    let mldsa65_public = mldsa65.public_key()?;
    let signature = mldsa65.sign(b"mldsa65")?;
    assert!(mldsa65_public.verify(b"mldsa65", &signature)?);
    let contextual_signature = mldsa65.sign_with_context(b"mldsa65-context", Some(b"ctx"))?;
    assert!(mldsa65_public.verify_with_context(
        b"mldsa65-context",
        &contextual_signature,
        Some(b"ctx")
    )?);
    let restored = Mldsa65PrivateKey::from_seed_representation(
        mldsa65.seed_representation()?,
        Some(&mldsa65_public),
    )?;
    assert_eq!(
        restored.public_key()?.raw_representation(),
        mldsa65_public.raw_representation()
    );

    let mldsa87 = Mldsa87PrivateKey::generate()?;
    let mldsa87_public = mldsa87.public_key()?;
    let signature = mldsa87.sign(b"mldsa87")?;
    assert!(mldsa87_public.verify(b"mldsa87", &signature)?);
    let contextual_signature = mldsa87.sign_with_context(b"mldsa87-context", Some(b"ctx"))?;
    assert!(mldsa87_public.verify_with_context(
        b"mldsa87-context",
        &contextual_signature,
        Some(b"ctx")
    )?);

    Ok(())
}
