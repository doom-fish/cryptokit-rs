# Changelog

## [0.2.4] - 2026-06-05

### Changed

- Added explicit SAFETY comments to unsafe pointer operations in error handling (CStr::from_ptr, libc::free calls, slice::from_raw_parts) to improve unsafe audit clarity.
- Updated README status line to reflect v0.2.3 compile-time availability guards.

## [0.2.3] - 2026-06-05

### Changed

- Added compile-time `@available(macOS 26.0, *)` attributes to all 32 `@_cdecl` thunks in `PostQuantum.swift` (ML-KEM, ML-DSA, Secure Enclave MLDSA65/MLDSA87/MLKEM768/MLKEM1024) and `@available(macOS 26.0, *)` / `@available(macOS 14.0, *)` to all 15 `@_cdecl` thunks in `HPKE.swift`.  These companion the existing runtime `guard #available` checks and make the bridge SDK-portable — downstream consumers building with a macOS 15 SDK no longer see unavailability errors for post-quantum symbols.

## [0.2.2] - 2026-05-17

### Added

- Typed SHA-256 / SHA-384 / SHA-512 / MD5 / SHA-1 digest values plus streaming hash state and `SHA2_*` compatibility aliases.
- Typed HMAC values, streaming HMAC state, verification helpers, and HKDF `extract` / `expand` wrappers.
- Typed `AES.GCM.Nonce` / `ChaChaPoly.Nonce` wrappers, sealed-box reconstruction helpers, and typed nonce APIs.
- Alternate P-256 / P-384 / P-521 key encodings (`compact`, `x963`, `compressed`, `pem`, `der`) across the generic and typed signing/key-agreement wrappers.
- Secure Enclave access-control and authentication-context builders, plus explicit-option creation / restore flows for P-256 and Secure Enclave post-quantum keys.
- New integration tests and numbered examples covering typed hashing, key representations, alternate encodings, and Secure Enclave option plumbing.

### Changed

- Bumped the crate version to `0.2.2` and refreshed the docs/coverage audit to reflect the filled CryptoKit surface.
- Kept the Swift bridge build baseline at macOS 10.15 while routing newer key-representation and Secure Enclave APIs through runtime availability checks.

## [0.2.1] - 2026-05-16

### Added

- `key_wrap`, `sha3`, `kem`, `mldsa`, and `hpke` modules plus root/prelude re-exports for `AES.KeyWrap`, SHA-3, KEM, ML-KEM, ML-DSA, XWing, and HPKE sender/recipient flows.
- Typed `P256` / `P384` / `P521` ECDSA signature wrappers with raw/DER conversions and typed signing/verification helpers.
- Secure Enclave `dataRepresentation` export/restore for P-256 signing and key-agreement keys, plus runtime-gated Secure Enclave ML-KEM / ML-DSA wrappers.
- New integration tests and numbered examples covering key wrap, SHA-3, typed ECDSA signatures, Secure Enclave restore, KEM/ML-DSA, HPKE, and Secure Enclave post-quantum probes.

### Changed

- Refreshed `README.md`, `COVERAGE.md`, and `COVERAGE_AUDIT.md` for the expanded CryptoKit surface.
- Kept the Swift bridge build baseline at macOS 10.15 while adding runtime `#available` guards for newer CryptoKit APIs.

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
