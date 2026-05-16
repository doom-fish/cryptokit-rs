use cryptokit::curve25519::X25519PrivateKey;
use cryptokit::{HpkeCiphersuite, HpkeRecipient, HpkeSender, Result};

fn main() -> Result<()> {
    let recipient = X25519PrivateKey::generate()?;
    let recipient_public = recipient.public_key()?;

    let mut sender = HpkeSender::new(
        &recipient_public,
        HpkeCiphersuite::CURVE25519_SHA256_CHACHA_POLY,
        b"example info",
    )?;
    let encapsulated = sender.encapsulated_key()?;
    let ciphertext = sender.seal_with_aad(b"doom fish", b"aad")?;

    let mut recipient_context = HpkeRecipient::new(
        &recipient,
        HpkeCiphersuite::CURVE25519_SHA256_CHACHA_POLY,
        b"example info",
        &encapsulated,
    )?;
    let plaintext = recipient_context.open_with_aad(&ciphertext, b"aad")?;

    println!("HPKE plaintext: {}", String::from_utf8_lossy(&plaintext));
    Ok(())
}
