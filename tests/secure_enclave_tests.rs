use cryptokit::p256::P256KeyAgreementPrivateKey;
use cryptokit::secure_enclave::{
    self, SecureEnclaveKeyAgreementPrivateKey, SecureEnclaveSigningPrivateKey,
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

    let enclave = SecureEnclaveKeyAgreementPrivateKey::generate()?;
    let software = P256KeyAgreementPrivateKey::generate()?;
    let enclave_secret = enclave.shared_secret(&software.public_key()?)?;
    let software_secret = software.shared_secret(&enclave.public_key()?)?;
    assert_eq!(enclave_secret.as_bytes(), software_secret.as_bytes());
    Ok(())
}
