use cryptokit::key_derivation::{self, KeyDerivationAlgorithm};
use cryptokit::p256::P256KeyAgreementPrivateKey;
use cryptokit::{CryptoKitError, Result};

#[test]
fn shared_secret_supports_hkdf_and_x963_derivations() -> Result<()> {
    let alice = P256KeyAgreementPrivateKey::generate()?;
    let bob = P256KeyAgreementPrivateKey::generate()?;
    let secret = alice.shared_secret(&bob.public_key()?)?;

    let hkdf = key_derivation::derive(
        &secret,
        KeyDerivationAlgorithm::HkdfSha512,
        b"salt",
        b"info",
        32,
    )?;
    let x963 = key_derivation::derive(
        &secret,
        KeyDerivationAlgorithm::X963Sha256,
        &[],
        b"shared-info",
        32,
    )?;
    assert_eq!(hkdf.as_bytes().len(), 32);
    assert_eq!(x963.as_bytes().len(), 32);
    Ok(())
}

#[test]
fn x963_rejects_non_empty_salt() -> Result<()> {
    let alice = P256KeyAgreementPrivateKey::generate()?;
    let bob = P256KeyAgreementPrivateKey::generate()?;
    let secret = alice.shared_secret(&bob.public_key()?)?;
    let result = key_derivation::derive(
        &secret,
        KeyDerivationAlgorithm::X963Sha384,
        b"salt",
        b"shared-info",
        16,
    );
    assert!(matches!(result, Err(CryptoKitError::InvalidArgument(_))));
    Ok(())
}
