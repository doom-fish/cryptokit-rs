use cryptokit::p256::P256KeyAgreementPrivateKey;
use cryptokit::secure_enclave::{
    self, SecureEnclaveKeyAgreementPrivateKey, SecureEnclaveMldsa65PrivateKey,
    SecureEnclaveMlkem768PrivateKey, SecureEnclaveSigningPrivateKey,
};
use cryptokit::Result;

#[test]
fn secure_enclave_availability_probe_is_safe() -> Result<()> {
    let _ = secure_enclave::is_available()?;
    Ok(())
}

#[test]
#[ignore = "requires Secure Enclave availability and keychain access"]
fn secure_enclave_round_trips_when_available() -> Result<()> {
    if !secure_enclave::is_available()? {
        return Ok(());
    }

    let signing = SecureEnclaveSigningPrivateKey::generate()?;
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"secure enclave")?;
    assert!(verifying.verify(b"secure enclave", &signature)?);
    let typed_signature = signing.sign_signature(b"secure enclave typed")?;
    assert!(verifying.verify_signature(b"secure enclave typed", &typed_signature)?);

    let signing_restored =
        SecureEnclaveSigningPrivateKey::from_data_representation(&signing.data_representation()?)?;
    assert_eq!(signing_restored.public_key()?.raw_representation(), verifying.raw_representation());

    let enclave = SecureEnclaveKeyAgreementPrivateKey::generate()?;
    let enclave_public_key = enclave.public_key()?;
    let restored_enclave =
        SecureEnclaveKeyAgreementPrivateKey::from_data_representation(&enclave.data_representation()?)?;
    assert_eq!(
        restored_enclave.public_key()?.raw_representation(),
        enclave_public_key.raw_representation()
    );

    let software = P256KeyAgreementPrivateKey::generate()?;
    let enclave_secret = enclave.shared_secret(&software.public_key()?)?;
    let software_secret = software.shared_secret(&enclave_public_key)?;
    let restored_secret = restored_enclave.shared_secret(&software.public_key()?)?;
    assert_eq!(enclave_secret.as_bytes(), software_secret.as_bytes());
    assert_eq!(restored_secret.as_bytes(), software_secret.as_bytes());
    Ok(())
}

#[test]
#[ignore = "requires Secure Enclave post-quantum availability and keychain access"]
fn secure_enclave_post_quantum_round_trips_when_available() -> Result<()> {
    if !secure_enclave::is_available()? {
        return Ok(());
    }

    let mldsa = SecureEnclaveMldsa65PrivateKey::generate()?;
    let mldsa_public = mldsa.public_key()?;
    let signature = mldsa.sign_with_context(b"secure enclave mldsa", Some(b"ctx"))?;
    assert!(mldsa_public.verify_with_context(b"secure enclave mldsa", &signature, Some(b"ctx"))?);
    let restored_mldsa =
        SecureEnclaveMldsa65PrivateKey::from_data_representation(&mldsa.data_representation()?)?;
    assert_eq!(
        restored_mldsa.public_key()?.raw_representation(),
        mldsa_public.raw_representation()
    );

    let mlkem = SecureEnclaveMlkem768PrivateKey::generate()?;
    let mlkem_public = mlkem.public_key()?;
    let encapsulation = mlkem_public.encapsulate()?;
    let decapsulated = mlkem.decapsulate(encapsulation.encapsulated())?;
    assert_eq!(decapsulated.as_bytes(), encapsulation.shared_secret().as_bytes());
    let restored_mlkem =
        SecureEnclaveMlkem768PrivateKey::from_data_representation(&mlkem.data_representation()?)?;
    assert_eq!(
        restored_mlkem.public_key()?.raw_representation(),
        mlkem_public.raw_representation()
    );

    Ok(())
}
