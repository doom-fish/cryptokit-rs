use cryptokit::mldsa::Mldsa65PrivateKey;
use cryptokit::Result;

fn main() -> Result<()> {
    let private_key = Mldsa65PrivateKey::generate()?;
    let public_key = private_key.public_key()?;
    let signature = private_key.sign_with_context(b"doom fish", Some(b"ctx"))?;

    println!(
        "ML-DSA signature verifies: {}",
        public_key.verify_with_context(b"doom fish", &signature, Some(b"ctx"))?
    );
    Ok(())
}
