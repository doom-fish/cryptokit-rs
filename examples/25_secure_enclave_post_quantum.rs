use cryptokit::secure_enclave::{self, SecureEnclaveMldsa65PrivateKey, SecureEnclaveMlkem768PrivateKey};
use cryptokit::Result;

fn main() -> Result<()> {
    if !secure_enclave::is_available()? {
        println!("Secure Enclave is unavailable on this Mac");
        return Ok(());
    }

    match SecureEnclaveMldsa65PrivateKey::generate() {
        Ok(private_key) => {
            let public_key = private_key.public_key()?;
            let signature = private_key.sign_with_context(b"doom fish", Some(b"ctx"))?;
            println!(
                "Secure Enclave ML-DSA verifies: {}",
                public_key.verify_with_context(b"doom fish", &signature, Some(b"ctx"))?
            );
        }
        Err(error) => println!("Secure Enclave ML-DSA unavailable: {error}"),
    }

    match SecureEnclaveMlkem768PrivateKey::generate() {
        Ok(private_key) => {
            let public_key = private_key.public_key()?;
            let encapsulation = public_key.encapsulate()?;
            let decapsulated = private_key.decapsulate(encapsulation.encapsulated())?;
            println!(
                "Secure Enclave ML-KEM matches: {}",
                decapsulated.as_bytes() == encapsulation.shared_secret().as_bytes()
            );
        }
        Err(error) => println!("Secure Enclave ML-KEM unavailable: {error}"),
    }

    Ok(())
}
