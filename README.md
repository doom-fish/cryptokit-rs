# cryptokit-rs

Safe Rust bindings for Apple's [CryptoKit](https://developer.apple.com/documentation/cryptokit) framework on macOS.

> **Status:** v0.2.2 fills the remaining audited CryptoKit feature gaps with typed SHA-2 / insecure digests, streaming hash/HMAC state, HKDF `extract` / `expand`, typed AEAD nonces, alternate NIST key encodings, and Secure Enclave access-control / authentication-context flows on top of the v0.2.1 surface.

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
- Adds typed SHA-2 / insecure digest values, streaming hash/HMAC state, typed HMAC codes, and HKDF `extract` / `expand` helpers.
- Adds typed `AES.GCM.Nonce` / `ChaChaPoly.Nonce` values plus alternate P-256 / P-384 / P-521 key encodings (`compact`, `x963`, `compressed`, `pem`, `der`).
- Adds `secure_enclave` P-256 and post-quantum access-control / authentication-context customization alongside restore/export flows.
- Keeps the Swift bridge build baseline at macOS 10.15 while using runtime `#available` checks for newer APIs such as `AES.KeyWrap`, SHA-3, HPKE, ML-KEM, ML-DSA, `XWing`, DER/PEM key encodings, compressed public keys, and newer HKDF entry points.
- Adds `COVERAGE.md`, 27 numbered examples, and 22 integration-test files.

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
- Newer APIs such as `AES.KeyWrap`, SHA-3, HPKE, ML-KEM, ML-DSA, `XWing`, Secure Enclave post-quantum keys, HKDF `extract` / `expand`, DER/PEM encodings, and compressed public keys are bridged with runtime availability checks while the crate still builds with a macOS 10.15 baseline.
- Secure Enclave examples and tests probe availability first and may skip on machines without the required hardware or usable keychain state.
- `COVERAGE.md` and `COVERAGE_AUDIT.md` track the audited `CryptoKit` surface; v0.2.2 fills the previously listed functional gaps and treats Swift-only error/meta utility families as exempt from the Rust binding surface.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
