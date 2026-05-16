use cryptokit::p256::P256KeyAgreementPrivateKey;
use cryptokit::secure_enclave::{
    self, SecureEnclaveKeyAgreementPrivateKey, SecureEnclaveSigningPrivateKey,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !secure_enclave::is_available()? {
        println!("Secure Enclave unavailable on this Mac; skipping example");
        return Ok(());
    }

    let signing = match SecureEnclaveSigningPrivateKey::generate() {
        Ok(key) => key,
        Err(error) => {
            println!("Secure Enclave signing unavailable ({error}); skipping example");
            return Ok(());
        }
    };
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"secure enclave example")?;
    assert!(verifying.verify(b"secure enclave example", &signature)?);

    let enclave = match SecureEnclaveKeyAgreementPrivateKey::generate() {
        Ok(key) => key,
        Err(error) => {
            println!("Secure Enclave key agreement unavailable ({error}); skipping example");
            return Ok(());
        }
    };
    let software = P256KeyAgreementPrivateKey::generate()?;
    let enclave_secret = enclave.shared_secret(&software.public_key()?)?;
    let software_secret = software.shared_secret(&enclave.public_key()?)?;
    assert_eq!(enclave_secret.as_bytes(), software_secret.as_bytes());
    println!("secure enclave signature bytes: {}", signature.len());
    Ok(())
}
