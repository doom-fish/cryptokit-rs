# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

### Security

- Secret types (`SymmetricKey`, `SigningPrivateKey`, `KeyAgreementPrivateKey`, the typed P-256 / P-384 / P-521 / Curve25519 private keys, the ML-KEM / ML-DSA / X-Wing private keys and `HashedAuthenticationCode`) keep their bytes in `Zeroizing` storage, redact `Debug`, and compare in constant time.
- Buffers crossing the Swift bridge are wiped before they are freed: Rust zeroizes the malloc copies, and Swift copies inputs into self-wiping `Data`, wipes outputs after copying them out, and wipes before freeing.
- `HashedAuthenticationCode` equality is constant-time, including comparisons against byte slices, vectors and arrays, so `computed == received` is safe.
- Shared-secret HKDF and ANSI X9.63 derivations call CryptoKit's `SharedSecret.hkdfDerivedSymmetricKey` / `x963DerivedSymmetricKey` instead of hand-written code that ignored the 255 × HashLen cap and wrapped its block counter.
- AES-CBC decryption failures are indistinguishable: one `DecryptionFailed` error without the CommonCrypto status. Empty and partial-block ciphertexts are rejected before `CCCrypt`, which otherwise reported success with bytes that were never decrypted.
- Secure Enclave access control rejects the deprecated `kSecAttrAccessibleAlways*` classes and classes without `ThisDeviceOnly`.

### Fixed

- Output lengths are validated before calling Swift (HKDF and HKDF-Expand 1..=255 × HashLen, X9.63 below HashLen × (2³² − 1), HPKE `export_secret` 1..=255 × Nh), and the Swift thunks use `Int(exactly:)` plus the same bounds, so oversized requests return `InvalidArgument` instead of aborting the process.
- The post-quantum and HPKE thunks no longer carry `@available` attributes that folded their runtime `#available` guards to `true`; on older macOS they return the "requires macOS N" error again instead of calling unavailable symbols.
- Removed `as!` force casts from the Secure Enclave post-quantum constructors.

### Changed

- **Breaking:** `SharedSecret` wraps CryptoKit's `SharedSecret`. `as_bytes()` / `into_bytes()` are replaced by `hazmat_raw_bytes()`, which returns `Zeroizing<Vec<u8>>`; prefer `key_derivation::derive_hkdf` / `derive_x963`. Equality is constant-time and the type is `Send + Sync`.
- **Breaking:** `SymmetricKey` no longer implements `Hash`. `SymmetricKey::into_bytes`, `into_raw_representation`, `into_integrity_checked_representation` and `HashedAuthenticationCode::into_bytes` return `Zeroizing<Vec<u8>>`.
- **Breaking:** private-key `x963_representation`, `der_representation` and `seed_representation` return `Zeroizing<Vec<u8>>`; private-key `pem_representation` returns `Zeroizing<String>`.
- **Breaking:** private-key constructors (`from_raw_representation`, `from_x963_representation`, `from_der_representation`, `from_seed_representation`, `from_integrity_checked_representation`) take `impl AsRef<[u8]>`.
- **Breaking:** `hmac_sha256`, `hmac_sha384` and `hmac_sha512` return `HashedAuthenticationCode<H>`; use `.as_bytes()` for the raw MAC. `HashedAuthenticationCode` and `MessageAuthenticationCode` no longer implement or require `Hash`.
- **Breaking:** AES-CBC moved from `cryptokit::aes_cbc` and the root/prelude `AesCbc` re-export to `cryptokit::hazmat::aes_cbc::AesCbc`.
- **Breaking:** the root and prelude `AesGcm` is now `aes_gcm::AesGcm` (sealed boxes and authenticated data), and `ChaChaPoly` replaces `ChaCha20Poly1305`.
- **Breaking:** Secure Enclave key creation (`generate_with_options` on `SecureEnclaveSigningPrivateKey`, `SecureEnclaveKeyAgreementPrivateKey`, `SecureEnclaveMldsa65PrivateKey`, `SecureEnclaveMldsa87PrivateKey`, `SecureEnclaveMlkem768PrivateKey` and `SecureEnclaveMlkem1024PrivateKey`) takes `Option<&AccessControl>`, `security-rs`'s wrapper around a real `SecAccessControlRef`, which the Swift bridge passes to CryptoKit instead of rebuilding an access control from flags. `None` still selects CryptoKit's own default (`AfterFirstUnlockThisDeviceOnly`, no flags).
- **Breaking:** Secure Enclave access control must use a `ThisDeviceOnly` protection class and include `PRIVATE_KEY_USAGE`; anything else returns `InvalidArgument` before a key is created.
- **Breaking:** the convenience default is `secure_enclave::default_access_control()`, `WhenUnlockedThisDeviceOnly` with `PRIVATE_KEY_USAGE`. 0.2's `SecureEnclaveAccessControl::default()` was `AfterFirstUnlockThisDeviceOnly` with no flags.
- **Breaking:** the crate depends on `security-rs` (`>=0.6, <0.7`), whose Swift bridge requires macOS 12, so binaries now need macOS 12 or later.
- **Breaking:** the raw `cryptokit::ffi` declarations for shared secrets, the combined AES-GCM / ChaChaPoly thunks and the Secure Enclave `*_generate_with_options` thunks (which take the `SecAccessControlRef` instead of an accessibility constant and flags) changed with the bridge, and `ffi::secure_enclave_accessibility` is removed.
- `rust-version` is now 1.82.

### Added

- `SharedSecret::hazmat_raw_bytes`.
- `secure_enclave::default_access_control()`, and re-exports of `security-rs`'s `AccessControl`, `AccessControlFlags` and `AccessControlProtection` from `secure_enclave`.
- Root and prelude re-exports of `HashedAuthenticationCode`, `AesGcmNonce`, `AesGcmSealedBox`, `ChaChaPoly`, `ChaChaPolyNonce` and `ChaChaPolySealedBox`, and a root re-export of `zeroize::Zeroizing`.

### Removed

- `symmetric::AesGcm`, `symmetric::ChaCha20Poly1305`, the `Vec`-returning dynamic `hmac()` and `hmac_sha256_code` / `hmac_sha384_code` / `hmac_sha512_code`.
- **Breaking:** `secure_enclave::{SecureEnclaveAccessControl, SecureEnclaveAccessControlFlags, SecureEnclaveAccessibility}`, duplicates of the `security-rs` types. Use `AccessControl::create(AccessControlProtection, AccessControlFlags)` (re-exported from `secure_enclave`) or `secure_enclave::default_access_control()`.

## [0.2.5] - 2026-05-19

- Bump MSRV from 1.70 to 1.76 to match fleet baseline.

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
