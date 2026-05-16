# cryptokit-rs

Safe Rust bindings for Apple's [CryptoKit](https://developer.apple.com/documentation/cryptokit) framework on macOS.

> **Status:** v0.1.0 covers the core CryptoKit surface doom-fish crates need first: SHA-family hashing, insecure MD5/SHA-1 compatibility hashes, HMAC, HKDF, AES-GCM, ChaCha20-Poly1305, Ed25519 / NIST signing keys, and ECDH key agreement.

## Quick start

```rust,no_run
use cryptokit::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let digest = sha256(b"hello")?;
    assert_eq!(digest.len(), 32);

    let key = SymmetricKey::generate(SymmetricKeySize::Bits256)?;
    let sealed = AesGcm::seal(b"doom fish", &key, None)?;
    let opened = AesGcm::open(&sealed, &key)?;
    assert_eq!(opened, b"doom fish");

    let signing = SigningPrivateKey::generate(SigningAlgorithm::Ed25519)?;
    let signature = signing.sign(b"hello")?;
    assert!(signing.public_key()?.verify(b"hello", &signature)?);

    Ok(())
}
```

## Highlights

- `SymmetricKey`, `SymmetricKeySize`, `AesGcm`, and `ChaCha20Poly1305`
- `sha256` / `sha384` / `sha512` / `md5` / `sha1`
- `hmac_sha256` / `hmac_sha384` / `hmac_sha512`
- `hkdf_sha256` plus `SharedSecret::hkdf_sha256`
- `SigningPrivateKey` / `SigningPublicKey` for P-256 / P-384 / P-521 and Ed25519
- `KeyAgreementPrivateKey` / `KeyAgreementPublicKey` for P-256 / P-384 / P-521 and X25519

## Smoke example

Run the end-to-end smoke test with:

```bash
cargo run --all-features --example 01_smoke
```

It checks the SHA-256 digest for `"hello"`, round-trips a 1KiB AES-GCM message with a generated 256-bit key, signs and verifies with Ed25519, and performs P-256 ECDH on both sides.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
