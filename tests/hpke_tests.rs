use cryptokit::curve25519::{X25519PrivateKey, X25519PublicKey};
use cryptokit::hpke::{HpkeCiphersuite, HpkeKem, HpkePublicKeySerialization};
use cryptokit::kem::{XWingMlkem768X25519PrivateKey, XWingMlkem768X25519PublicKey};
use cryptokit::p256::P256KeyAgreementPrivateKey;
use cryptokit::{HpkeRecipient, HpkeSender, Result, SymmetricKey};

#[test]
fn hpke_round_trips_for_diffie_hellman_and_kem_modes() -> Result<()> {
    let recipient = X25519PrivateKey::generate()?;
    let recipient_public = recipient.public_key()?;
    let serialized = recipient_public.hpke_representation(HpkeKem::Curve25519HkdfSha256)?;
    let parsed =
        X25519PublicKey::from_hpke_serialization(&serialized, HpkeKem::Curve25519HkdfSha256)?;
    assert_eq!(
        parsed.raw_representation(),
        recipient_public.raw_representation()
    );

    let mut sender = HpkeSender::new(
        &recipient_public,
        HpkeCiphersuite::CURVE25519_SHA256_CHACHA_POLY,
        b"x25519 info",
    )?;
    let encapsulated = sender.encapsulated_key()?;
    let ciphertext = sender.seal_with_aad(b"x25519 hpke", b"aad")?;
    let exported = sender.export_secret(b"context", 32)?;

    let mut recipient_context = HpkeRecipient::new(
        &recipient,
        HpkeCiphersuite::CURVE25519_SHA256_CHACHA_POLY,
        b"x25519 info",
        &encapsulated,
    )?;
    assert_eq!(
        recipient_context.open_with_aad(&ciphertext, b"aad")?,
        b"x25519 hpke"
    );
    assert_eq!(
        recipient_context.export_secret(b"context", 32)?.as_bytes(),
        exported.as_bytes()
    );

    let authenticated_recipient = P256KeyAgreementPrivateKey::generate()?;
    let authenticated_recipient_public = authenticated_recipient.public_key()?;
    let authentication_key = P256KeyAgreementPrivateKey::generate()?;
    let psk = SymmetricKey::from_bytes(vec![0x44; 32]);

    let mut authenticated_sender = HpkeSender::new_authenticated_with_psk(
        &authenticated_recipient_public,
        HpkeCiphersuite::P256_SHA256_AES_GCM_256,
        b"p256 info",
        &authentication_key,
        &psk,
        b"psk-id",
    )?;
    let authenticated_encapsulated = authenticated_sender.encapsulated_key()?;
    let authenticated_ciphertext = authenticated_sender.seal(b"p256 hpke")?;

    let mut authenticated_recipient_context = HpkeRecipient::new_authenticated_with_psk(
        &authenticated_recipient,
        HpkeCiphersuite::P256_SHA256_AES_GCM_256,
        b"p256 info",
        &authenticated_encapsulated,
        &authentication_key.public_key()?,
        &psk,
        b"psk-id",
    )?;
    assert_eq!(
        authenticated_recipient_context.open(&authenticated_ciphertext)?,
        b"p256 hpke"
    );

    let kem_recipient = XWingMlkem768X25519PrivateKey::generate()?;
    let kem_public = kem_recipient.public_key()?;
    let kem_serialized = kem_public.hpke_representation(HpkeKem::XWingMlkem768X25519)?;
    let kem_parsed = XWingMlkem768X25519PublicKey::from_hpke_serialization(
        &kem_serialized,
        HpkeKem::XWingMlkem768X25519,
    )?;
    assert_eq!(
        kem_parsed.raw_representation(),
        kem_public.raw_representation()
    );

    let mut kem_sender = HpkeSender::new_with_kem(
        &kem_public,
        HpkeCiphersuite::XWING_MLKEM768_X25519_SHA256_AES_GCM_256,
        b"xwing info",
    )?;
    let kem_encapsulated = kem_sender.encapsulated_key()?;
    let kem_ciphertext = kem_sender.seal_with_aad(b"xwing hpke", b"aad")?;
    let kem_exported = kem_sender.export_secret(b"context", 32)?;

    let mut kem_recipient_context = HpkeRecipient::new_with_kem(
        &kem_recipient,
        HpkeCiphersuite::XWING_MLKEM768_X25519_SHA256_AES_GCM_256,
        b"xwing info",
        &kem_encapsulated,
    )?;
    assert_eq!(
        kem_recipient_context.open_with_aad(&kem_ciphertext, b"aad")?,
        b"xwing hpke"
    );
    assert_eq!(
        kem_recipient_context
            .export_secret(b"context", 32)?
            .as_bytes(),
        kem_exported.as_bytes()
    );

    Ok(())
}
