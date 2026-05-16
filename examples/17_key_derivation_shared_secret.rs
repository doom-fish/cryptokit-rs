use cryptokit::key_derivation::{self, KeyDerivationAlgorithm};
use cryptokit::p256::P256KeyAgreementPrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = P256KeyAgreementPrivateKey::generate()?;
    let bob = P256KeyAgreementPrivateKey::generate()?;
    let secret = alice.shared_secret(&bob.public_key()?)?;
    let hkdf = key_derivation::derive(
        &secret,
        KeyDerivationAlgorithm::HkdfSha256,
        b"salt",
        b"info",
        32,
    )?;
    let x963 = key_derivation::derive(
        &secret,
        KeyDerivationAlgorithm::X963Sha512,
        &[],
        b"shared-info",
        32,
    )?;
    assert_eq!(hkdf.as_bytes().len(), 32);
    assert_eq!(x963.as_bytes().len(), 32);
    println!(
        "derived key lengths: {}, {}",
        hkdf.as_bytes().len(),
        x963.as_bytes().len()
    );
    Ok(())
}
