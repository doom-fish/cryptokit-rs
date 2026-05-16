use cryptokit::secure_enclave::{self, SecureEnclaveSigningPrivateKey};
use cryptokit::Result;

fn main() -> Result<()> {
    if !secure_enclave::is_available()? {
        println!("Secure Enclave is unavailable on this Mac");
        return Ok(());
    }

    let signing = SecureEnclaveSigningPrivateKey::generate()?;
    let restored =
        SecureEnclaveSigningPrivateKey::from_data_representation(&signing.data_representation()?)?;

    println!(
        "Restored public key matches: {}",
        restored.public_key()?.raw_representation() == signing.public_key()?.raw_representation()
    );
    Ok(())
}
