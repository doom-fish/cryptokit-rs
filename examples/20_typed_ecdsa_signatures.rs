use cryptokit::p256::P256SigningPrivateKey;
use cryptokit::Result;

fn main() -> Result<()> {
    let signing = P256SigningPrivateKey::generate()?;
    let verifying = signing.public_key()?;

    let signature = signing.sign_signature(b"typed signature example")?;
    let der = signature.der_representation()?;
    let roundtrip = cryptokit::p256::P256EcdsaSignature::from_der_representation(der)?;

    println!(
        "Typed signature verifies: {}",
        verifying.verify_signature(b"typed signature example", &roundtrip)?
    );
    Ok(())
}
