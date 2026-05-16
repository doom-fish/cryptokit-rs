# cryptokit-rs

Safe Rust bindings for Apple's [CryptoKit](https://developer.apple.com/documentation/cryptokit) framework on macOS.

> **Status:** v0.2.1 adds `AES.KeyWrap`, SHA-3, HPKE, KEM / ML-KEM / ML-DSA / XWing, typed `P256` / `P384` / `P521` ECDSA signatures, Secure Enclave restore flows, and Secure Enclave post-quantum wrappers on top of the v0.2.0 surface.

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

- Preserves the original root API (`AesGcm`, `ChaCha20Poly1305`, `SigningPrivateKey`, `KeyAgreementPrivateKey`) while adding per-area modules and root/prelude re-exports for newer `CryptoKit` families.
- Adds `key_wrap::AesKeyWrap`, `sha3::{Sha3_256, Sha3_384, Sha3_512}`, `kem`, `mldsa`, and `hpke::{HpkeSender, HpkeRecipient}` wrappers.
- Adds typed `P256` / `P384` / `P521` ECDSA signature values with raw and DER conversions.
- Adds `secure_enclave` P-256 `dataRepresentation` restore/export plus runtime-gated Secure Enclave ML-KEM / ML-DSA wrappers.
- Keeps the Swift bridge build baseline at macOS 10.15 while using runtime `#available` checks for newer APIs such as `AES.KeyWrap`, SHA-3, HPKE, ML-KEM, ML-DSA, and `XWing`.
- Adds `COVERAGE.md`, 25 numbered examples, and 21 integration-test files.

## Area modules

- `symmetric_key`
- `aes_gcm`
- `aes_cbc`
- `key_wrap`
- `chacha_poly`
- `p256`, `p384`, `p521`, `curve25519`
- `hkdf`, `hmac`, `sha`, `sha3`, `insecure`
- `hpke`, `kem`, `mldsa`
- `key_agreement`, `key_derivation`, `nist`, `secure_enclave`

## Running everything

```bash
cargo clippy --all-targets -- -D warnings
cargo test
for ex in examples/*.rs; do cargo run --example "$(basename "$ex" .rs)"; done
```

## Coverage notes

- AES-CBC is implemented through a Swift/CommonCrypto compatibility bridge because `CryptoKit` itself does not expose CBC mode on macOS.
- Newer APIs such as `AES.KeyWrap`, SHA-3, HPKE, ML-KEM, ML-DSA, `XWing`, and Secure Enclave post-quantum keys are bridged with runtime availability checks while the crate still builds with a macOS 10.15 baseline.
- Secure Enclave examples and tests probe availability first and may skip on machines without the required hardware or usable keychain state.
- `COVERAGE.md` and `COVERAGE_AUDIT.md` track implemented, partial, and remaining `CryptoKit` surface area.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
