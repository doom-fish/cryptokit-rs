# Changelog

## [0.2.0] - 2026-05-16

### Added

- Per-area Rust modules for `symmetric_key`, `aes_gcm`, `aes_cbc`, `chacha_poly`, `p256`, `p384`, `p521`, `curve25519`, `hkdf`, `hmac`, `sha`, `insecure`, `key_agreement`, `key_derivation`, `nist`, and `secure_enclave`.
- AES-GCM and ChaCha20-Poly1305 sealed-box helpers with authenticated-data support and nonce/ciphertext/tag accessors.
- AES-CBC PKCS#7 interoperability via a Swift/CommonCrypto compatibility bridge.
- Curve-specific signing and key-agreement wrappers for P-256 / P-384 / P-521 plus Ed25519 / X25519 convenience types.
- HKDF-SHA384 / HKDF-SHA512 and shared-secret HKDF / ANSI X9.63 derivation helpers.
- Secure Enclave-backed P-256 signing and key-agreement wrappers using retained Swift handles.
- `COVERAGE.md`, 16 new integration-test files, and numbered examples covering every logical area.

## [0.1.0] - 2026-05-16

### Added

- `SymmetricKey`, `SymmetricKeySize`, `AesGcm`, and `ChaCha20Poly1305` wrappers over `CryptoKit` symmetric-key and AEAD APIs.
- Hashing helpers for `SHA256`, `SHA384`, `SHA512`, `Insecure.MD5`, and `Insecure.SHA1`.
- HMAC helpers for SHA-256 / SHA-384 / SHA-512.
- HKDF-SHA256 support for generic symmetric key material plus `SharedSecret` derivation.
- Signing-key wrappers for P-256 / P-384 / P-521 and Ed25519 raw representations, signing, and verification.
- Key-agreement wrappers for P-256 / P-384 / P-521 and X25519 raw representations, public-key derivation, and shared-secret extraction.
- SwiftPM bridge under `swift-bridge/` with `ck_*` exports and a smoke example `examples/01_smoke.rs`.
