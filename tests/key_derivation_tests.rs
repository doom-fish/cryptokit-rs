use cryptokit::curve25519::{X25519PrivateKey, X25519PublicKey};
use cryptokit::hkdf::{hkdf, HkdfAlgorithm};
use cryptokit::key_derivation::{self, KeyDerivationAlgorithm};
use cryptokit::p256::P256KeyAgreementPrivateKey;
use cryptokit::sha::ShaAlgorithm;
use cryptokit::{sha256, CryptoKitError, Result, SharedSecret, SymmetricKey};

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

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap_or_default())
        .collect()
}

fn rfc7748_shared_secret() -> Result<SharedSecret> {
    let alice = X25519PrivateKey::from_raw_representation(decode_hex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ))?;
    let bob_public = X25519PublicKey::from_raw_representation(decode_hex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    ))?;
    alice.shared_secret(&bob_public)
}

#[test]
fn shared_secret_matches_rfc_7748_and_redacts_debug() -> Result<()> {
    let secret = rfc7748_shared_secret()?;
    assert_eq!(
        secret.hazmat_raw_bytes().as_slice(),
        decode_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    );
    assert_eq!(format!("{secret:?}"), "SharedSecret { .. }");

    let copy = secret.clone();
    drop(secret);
    assert_eq!(copy, rfc7748_shared_secret()?);

    let other = X25519PrivateKey::generate()?.shared_secret(&X25519PrivateKey::generate()?.public_key()?)?;
    assert_ne!(copy, other);
    Ok(())
}

#[test]
fn shared_secret_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SharedSecret>();
}

#[test]
fn shared_secret_hkdf_matches_generic_hkdf() -> Result<()> {
    let secret = rfc7748_shared_secret()?;
    let input_key_material = SymmetricKey::from_bytes(secret.hazmat_raw_bytes().as_slice());
    for (algorithm, output_len) in [
        (HkdfAlgorithm::Sha256, 42),
        (HkdfAlgorithm::Sha384, 100),
        (HkdfAlgorithm::Sha512, 255 * 64),
    ] {
        let derived = key_derivation::derive_hkdf(&secret, algorithm, b"salt", b"info", output_len)?;
        let expected = hkdf(algorithm, &input_key_material, b"salt", b"info", output_len)?;
        assert_eq!(derived, expected);
        assert_eq!(derived.as_bytes().len(), output_len);
    }
    assert_eq!(
        secret.hkdf_sha256(b"salt", b"info", 32)?,
        hkdf(HkdfAlgorithm::Sha256, &input_key_material, b"salt", b"info", 32)?
    );
    Ok(())
}

#[test]
fn shared_secret_x963_matches_ansi_x963_construction() -> Result<()> {
    let secret = rfc7748_shared_secret()?;
    let raw = secret.hazmat_raw_bytes();
    let block = |counter: u32| -> Result<Vec<u8>> {
        let mut input = raw.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(b"shared-info");
        sha256(&input)
    };
    let mut expected = block(1)?;
    expected.extend_from_slice(&block(2)?);
    expected.truncate(40);

    let derived = key_derivation::derive_x963(&secret, ShaAlgorithm::Sha256, b"shared-info", 40)?;
    assert_eq!(derived.as_bytes(), expected.as_slice());
    Ok(())
}

#[test]
fn shared_secret_derivations_reject_out_of_range_lengths() -> Result<()> {
    let secret = rfc7748_shared_secret()?;
    for output_len in [0, 255 * 32 + 1, usize::MAX] {
        let result = key_derivation::derive_hkdf(&secret, HkdfAlgorithm::Sha256, b"", b"", output_len);
        assert!(matches!(result, Err(CryptoKitError::InvalidArgument(_))));
    }
    assert_eq!(
        key_derivation::derive_hkdf(&secret, HkdfAlgorithm::Sha256, b"", b"", 255 * 32)?
            .as_bytes()
            .len(),
        255 * 32
    );
    for output_len in [0, usize::MAX] {
        let result = key_derivation::derive_x963(&secret, ShaAlgorithm::Sha512, b"", output_len);
        assert!(matches!(result, Err(CryptoKitError::InvalidArgument(_))));
    }
    Ok(())
}
