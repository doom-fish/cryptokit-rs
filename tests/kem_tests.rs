use cryptokit::kem::{
    Mlkem1024PrivateKey, Mlkem768PrivateKey, XWingMlkem768X25519PrivateKey,
};
use cryptokit::Result;

#[test]
fn post_quantum_kems_round_trip() -> Result<()> {
    let mlkem768 = Mlkem768PrivateKey::generate()?;
    let mlkem768_public = mlkem768.public_key()?;
    let mlkem768_encapsulation = mlkem768_public.encapsulate()?;
    let mlkem768_decapsulated = mlkem768.decapsulate(mlkem768_encapsulation.encapsulated())?;
    assert_eq!(
        mlkem768_decapsulated.as_bytes(),
        mlkem768_encapsulation.shared_secret().as_bytes()
    );
    let mlkem768_restored =
        Mlkem768PrivateKey::from_seed_representation(mlkem768.seed_representation()?, Some(&mlkem768_public))?;
    assert_eq!(
        mlkem768_restored.public_key()?.raw_representation(),
        mlkem768_public.raw_representation()
    );

    let mlkem1024 = Mlkem1024PrivateKey::generate()?;
    let mlkem1024_public = mlkem1024.public_key()?;
    let mlkem1024_encapsulation = mlkem1024_public.encapsulate()?;
    let mlkem1024_decapsulated = mlkem1024.decapsulate(mlkem1024_encapsulation.encapsulated())?;
    assert_eq!(
        mlkem1024_decapsulated.as_bytes(),
        mlkem1024_encapsulation.shared_secret().as_bytes()
    );

    let xwing = XWingMlkem768X25519PrivateKey::generate()?;
    let xwing_public = xwing.public_key()?;
    let xwing_encapsulation = xwing_public.encapsulate()?;
    let xwing_decapsulated = xwing.decapsulate(xwing_encapsulation.encapsulated())?;
    assert_eq!(
        xwing_decapsulated.as_bytes(),
        xwing_encapsulation.shared_secret().as_bytes()
    );
    let xwing_restored = XWingMlkem768X25519PrivateKey::from_seed_representation(
        xwing.seed_representation()?,
        Some(&xwing_public),
    )?;
    assert_eq!(
        xwing_restored.public_key()?.raw_representation(),
        xwing_public.raw_representation()
    );

    Ok(())
}
