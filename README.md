# cryptokit-rs

Safe Rust bindings for Apple's [CryptoKit](https://developer.apple.com/documentation/cryptokit) framework on macOS.

> **Status:** v0.3.0 is a security release with breaking changes: secret types are zeroized, redacted from `Debug` and compared in constant time; shared-secret key derivation uses CryptoKit's own HKDF and ANSI X9.63; AES-CBC moved to `hazmat`. See `CHANGELOG.md` for migration notes. The bridge covers the symmetric encryption, signing, key agreement, key derivation, hashing, HPKE, Secure Enclave and post-quantum (ML-KEM, ML-DSA, X-Wing) families of the macOS 26 SDK; see [Coverage notes](#coverage-notes) for what is not wrapped.

## Installation

```toml
[dependencies]
cryptokit-rs = "0.3.0"
```

The library is imported as `cryptokit`. Building requires macOS with Xcode 26 or newer (the macOS 26 SDK); the resulting binaries run on macOS 10.15 and later, and APIs that need a newer OS return an error at runtime.

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

- Root and prelude re-exports for the common types (`SymmetricKey`, `AesGcm`, `ChaChaPoly`, `SigningPrivateKey`, `KeyAgreementPrivateKey`, `SharedSecret`, HMAC/HKDF/SHA helpers) plus per-area modules for every `CryptoKit` family.
- Adds `key_wrap::AesKeyWrap`, `sha3::{Sha3_256, Sha3_384, Sha3_512}`, `kem`, `mldsa`, and `hpke::{HpkeSender, HpkeRecipient}` wrappers.
- Adds typed SHA-2 / insecure digest values, streaming hash/HMAC state, typed HMAC codes, and HKDF `extract` / `expand` helpers.
- Adds typed `AES.GCM.Nonce` / `ChaChaPoly.Nonce` values plus alternate P-256 / P-384 / P-521 key encodings (`compact`, `x963`, `compressed`, `pem`, `der`).
- Adds `secure_enclave` P-256 and post-quantum access-control / authentication-context customization alongside restore/export flows.
- Keeps the Swift bridge build baseline at macOS 10.15 while using runtime `#available` checks for newer APIs such as `AES.KeyWrap`, SHA-3, HPKE, ML-KEM, ML-DSA, `XWing`, DER/PEM key encodings, compressed public keys, and newer HKDF entry points.
- Adds `COVERAGE.md`, 27 numbered examples, and 22 integration-test files.

## Area modules

- `symmetric_key`
- `aes_gcm`
- `hazmat::aes_cbc`
- `key_wrap`
- `chacha_poly`
- `p256`, `p384`, `p521`, `curve25519`
- `hkdf`, `hmac`, `sha`, `sha3`, `insecure`
- `hpke`, `kem`, `mldsa`
- `key_agreement`, `key_derivation`, `nist`, `secure_enclave`

## Security notes

- `SymmetricKey`, private keys, ML-KEM/ML-DSA private keys and `HashedAuthenticationCode` (also used for HKDF pseudo-random keys) wipe their memory on drop, print only non-secret metadata from `Debug`, and compare in constant time. Secret exports (`into_bytes`, `x963_representation`, `der_representation`, `pem_representation`, `seed_representation`, ...) return `Zeroizing` values. Buffers passed across the Swift bridge are wiped before they are freed.
- Verify a received MAC with `computed == received` (constant-time against byte slices, vectors and arrays) or `Hmac::<H>::is_valid_authentication_code`.
- `SharedSecret` stays inside `CryptoKit`. Derive keys with `key_derivation::derive_hkdf` / `derive_x963`; the raw key-agreement output is only available through `SharedSecret::hazmat_raw_bytes()`.
- `hazmat::aes_cbc::AesCbc` is unauthenticated CBC with a caller-supplied IV. All decryption failures return the same error, but `CommonCrypto` does not reliably reject malformed padding, so authenticate ciphertexts separately or use `AesGcm` / `ChaChaPoly`.
- Secure Enclave access control accepts only the `ThisDeviceOnly` accessibility classes and must include `PRIVATE_KEY_USAGE`; `SecureEnclaveAccessControl::default()` matches the `CryptoKit` default.

## Running everything

```bash
cargo clippy --all-targets -- -D warnings
cargo test
for ex in examples/*.rs; do cargo run --example "$(basename "$ex" .rs)"; done
```

## Coverage notes

- AES-CBC is implemented through a Swift/CommonCrypto compatibility bridge because `CryptoKit` itself does not expose CBC mode on macOS.
- Newer APIs such as `AES.KeyWrap`, SHA-3, HPKE, ML-KEM, ML-DSA, `XWing`, Secure Enclave post-quantum keys, HKDF `extract` / `expand`, DER/PEM encodings, and compressed public keys are bridged with runtime availability checks against a macOS 10.15 deployment target.
- Secure Enclave examples and tests probe availability first and may skip on machines without the required hardware or usable keychain state.
- `COVERAGE.md` and `COVERAGE_AUDIT.md` track the audited `CryptoKit` surface as 56 collapsed symbol families from the macOS 26.2 SDK. The "100%" figure is measured over those families, not over individual symbols.
- Not wrapped: the macOS 27 additions (in-place detached-tag `AES.GCM` / `ChaChaPoly` seal and open, `SymmetricKey(copyingWithZeroing:)` and `SymmetricKey(size:initializingWith:)`, `KEM` `OneTimePrivateKey` types for ML-KEM and X-Wing, and the `RawSpan` / `OutputRawSpan` overloads of HMAC, HKDF and the hash functions).
- The raw `cryptokit::ffi` declarations are not part of the safe surface and are not counted as coverage.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
