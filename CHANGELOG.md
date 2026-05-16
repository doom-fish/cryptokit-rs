# Changelog

## [0.1.0] - 2026-05-16

### Added

- `SymmetricKey`, `SymmetricKeySize`, `AesGcm`, and `ChaCha20Poly1305` wrappers over `CryptoKit` symmetric-key and AEAD APIs.
- Hashing helpers for `SHA256`, `SHA384`, `SHA512`, `Insecure.MD5`, and `Insecure.SHA1`.
- HMAC helpers for SHA-256 / SHA-384 / SHA-512.
- HKDF-SHA256 support for generic symmetric key material plus `SharedSecret` derivation.
- Signing-key wrappers for P-256 / P-384 / P-521 and Ed25519 raw representations, signing, and verification.
- Key-agreement wrappers for P-256 / P-384 / P-521 and X25519 raw representations, public-key derivation, and shared-secret extraction.
- SwiftPM bridge under `swift-bridge/` with `ck_*` exports and a smoke example `examples/01_smoke.rs`.
