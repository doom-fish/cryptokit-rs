# cryptokit-rs

Safe Rust bindings for Apple's [CryptoKit](https://developer.apple.com/documentation/cryptokit) framework on macOS.

> **Status:** v0.2.0 adds per-area coverage for `SymmetricKey`, `AES.GCM`, AES-CBC compatibility, `ChaChaPoly`, `P256`, `P384`, `P521`, `Curve25519`, `HKDF`, `HMAC`, `SHA`, `SecureEnclave`, `NIST`, insecure `MD5` / `SHA1`, generic key agreement, and shared-secret key derivation.

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

- Preserves the original root API (`AesGcm`, `ChaCha20Poly1305`, `SigningPrivateKey`, `KeyAgreementPrivateKey`) while adding per-area modules.
- Adds `aes_gcm` / `chacha_poly` sealed-box helpers with nonce, ciphertext, tag, and authenticated-data support.
- Adds `aes_cbc::AesCbc` for PKCS#7-padded CBC interoperability.
- Adds curve-specific modules for `p256`, `p384`, `p521`, and `curve25519` on top of the generic signing/key-agreement API.
- Adds `key_derivation` helpers for shared-secret HKDF and ANSI X9.63 derivation.
- Adds `secure_enclave` P-256 signing/key-agreement wrappers that gracefully skip when the hardware or keychain is unavailable.
- Adds `COVERAGE.md`, 17 numbered examples, and 16 integration-test files.

## Area modules

- `symmetric_key`
- `aes_gcm`
- `aes_cbc`
- `chacha_poly`
- `p256`, `p384`, `p521`, `curve25519`
- `hkdf`, `hmac`, `sha`, `insecure`
- `key_agreement`, `key_derivation`, `nist`, `secure_enclave`

## Running everything

```bash
cargo clippy --all-targets -- -D warnings
cargo test
for ex in examples/*.rs; do cargo run --example "$(basename "$ex" .rs)"; done
```

## Coverage notes

- AES-CBC is implemented through a Swift/CommonCrypto compatibility bridge because `CryptoKit` itself does not expose CBC mode on macOS.
- Secure Enclave examples and tests probe availability first and may skip on machines without the required hardware or usable keychain state.
- `COVERAGE.md` tracks implemented, partial, and intentionally skipped `CryptoKit` surface area.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
