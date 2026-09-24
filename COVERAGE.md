# CryptoKit coverage audit

Audited against the macOS 26.2 SDK CryptoKit surface, with the crate organized by logical area. Each row is a logical area, not a symbol count; the macOS 27 additions listed under "Not wrapped" are outside this table.

Legend:

- ✅ implemented
- 🟡 partial
- ⏭️ skipped

## Logical areas covered in v0.3.0

| Area | Swift bridge | Rust module | Status | Notes |
| --- | --- | --- | --- | --- |
| SymmetricKey | `Symmetric.swift`, `SymmetricKey.swift` | `src/symmetric_key.rs` | ✅ | Generates 128/192/256-bit keys and reports supported sizes. |
| AESGCM | `AESGCM.swift` | `src/aes_gcm.rs` | ✅ | Combined sealed boxes, nonce/ciphertext/tag accessors, explicit nonce support, and authenticated data. |
| AESCBC | `AESCBC.swift` | `src/hazmat/aes_cbc.rs` | ✅ | Unauthenticated PKCS#7 CBC interoperability via Swift/CommonCrypto (CryptoKit has no CBC mode). Lives in `hazmat`; every decryption failure returns the same error. |
| AESKeyWrap | `KeyWrap.swift` | `src/key_wrap.rs` | ✅ | Wraps and unwraps key material through `AES.KeyWrap` on macOS 12+. |
| ChaChaPoly | `ChaChaPoly.swift` | `src/chacha_poly.rs` | ✅ | Combined sealed boxes, typed nonce values, sealed-box reconstruction, and authenticated-data support. |
| P256 | `PublicKey.swift`, `P256.swift` | `src/p256.rs` | ✅ | Signing, verification, key agreement, typed ECDSA signatures, raw/compact/x963/compressed/pem/der encodings, and compact-representable generation. |
| P384 | `PublicKey.swift`, `P384.swift` | `src/p384.rs` | ✅ | Signing, verification, key agreement, typed ECDSA signatures, raw/compact/x963/compressed/pem/der encodings, and compact-representable generation. |
| P521 | `PublicKey.swift`, `P521.swift` | `src/p521.rs` | ✅ | Signing, verification, key agreement, typed ECDSA signatures, raw/compact/x963/compressed/pem/der encodings, and compact-representable generation. |
| Curve25519 | `PublicKey.swift`, `Curve25519.swift` | `src/curve25519.rs` | ✅ | Ed25519 signing/verification plus X25519 key agreement wrappers and HPKE serialization helpers. |
| HKDF | `HKDF.swift` | `src/hkdf.rs` | ✅ | HKDF-SHA256 / SHA384 / SHA512 derive, extract, and expand over symmetric key material. |
| HMAC | `HMAC.swift` | `src/hmac.rs` | ✅ | One-shot and streaming HMAC-SHA256 / SHA384 / SHA512 with typed codes that compare in constant time, plus `isValidAuthenticationCode` helpers. |
| SHA | `Hashing.swift`, `SHA.swift` | `src/sha.rs` | ✅ | One-shot and streaming SHA-256 / SHA-384 / SHA-512 with typed digests and `SHA2_*` aliases. |
| SHA3 | `SHA3.swift` | `src/sha3.rs` | ✅ | SHA3-256 / SHA3-384 / SHA3-512 one-shot and streaming wrappers with typed digest values on macOS 26+. |
| HPKE | `HPKE.swift` | `src/hpke.rs` | ✅ | Diffie-Hellman and KEM sender/recipient contexts, authenticated and PSK modes, `exportSecret`, and public-key serialization. |
| KEM | `PostQuantum.swift` | `src/kem.rs` | ✅ | Encapsulation/decapsulation for `MLKEM768`, `MLKEM1024`, and `XWingMLKEM768X25519` on macOS 26+. |
| MLDSA | `PostQuantum.swift` | `src/mldsa.rs` | ✅ | ML-DSA 65 / 87 signing and verification with optional context bytes on macOS 26+. |
| SecureEnclave | `SecureEnclave.swift`, `PostQuantum.swift` | `src/secure_enclave.rs` | ✅ | Availability probe, P-256 signing/key-agreement, access control (`security-rs`'s `AccessControl`, whose `SecAccessControlRef` is passed to CryptoKit; ThisDeviceOnly classes and `PRIVATE_KEY_USAGE` required) and authentication-context customization, restore/export flows, and Secure Enclave ML-KEM / ML-DSA wrappers. |
| NIST | `NIST.swift` | `src/nist.rs` | ✅ | P-256 / P-384 / P-521 discovery and generic helper APIs. |
| Insecure (MD5/SHA1) | `Hashing.swift`, `Insecure.swift` | `src/insecure.rs` | ✅ | One-shot and streaming `Insecure.MD5` / `Insecure.SHA1` with typed digest values. |
| KeyAgreement | `KeyAgreement.swift`, `PublicKey.swift` | `src/key_agreement.rs` | ✅ | Generic P-256 / P-384 / P-521 / X25519 key-agreement wrappers, trait-based Diffie-Hellman helpers, and support discovery. |
| KeyDerivation | `KeyDerivation.swift` | `src/key_derivation.rs` | ✅ | `SharedSecret.hkdfDerivedSymmetricKey` and `x963DerivedSymmetricKey` with SHA-256 / SHA-384 / SHA-512 on a retained CryptoKit `SharedSecret`. |

## Coverage notes

- The crate still builds its Swift bridge with a macOS 10.15 deployment target; newer APIs are exposed with runtime `#available` checks rather than a higher build baseline. The `security-rs` dependency (the Secure Enclave `AccessControl` type) requires macOS 12, so binaries need macOS 12 or later.
- `AES.KeyWrap` requires macOS 12+, HPKE requires macOS 14+, DER/PEM encodings and native HKDF `extract` / `expand` require macOS 11+, compressed public keys require macOS 13+, and SHA-3 / ML-KEM / ML-DSA / XWing / Secure Enclave post-quantum APIs require macOS 26+.
- Secure Enclave examples and tests probe availability first and may skip on machines without the required hardware or usable keychain state.
- `COVERAGE_AUDIT.md` records 56 collapsed symbol families from the macOS 26.2 SDK; its "100%" is measured over those families. The raw `cryptokit::ffi` declarations are not counted as safe coverage.

## Not wrapped

| API | SDK | Reason |
| --- | --- | --- |
| `AES.GCM` / `ChaChaPoly` `seal(inPlace:...)` / `open(inPlace:...)` with detached tags | macOS 27.0 | Not bridged yet; the combined sealed-box APIs cover the same algorithms. |
| `SymmetricKey(copyingWithZeroing:)`, `SymmetricKey(size:initializingWith:)`, `bytes` | macOS 27.0 | Swift span conveniences; `SymmetricKey::from_bytes` and `as_bytes` provide the Rust equivalents. |
| `KEMOneTimePrivateKey` and `MLKEM768` / `MLKEM1024` / `XWingMLKEM768X25519` `OneTimePrivateKey` | macOS 27.0 | Not bridged yet. |
| `RawSpan` / `OutputRawSpan` overloads of `HMAC`, `HKDF` and `HashFunction` | macOS 27.0 | Swift span conveniences over APIs that are already bridged. |

## Additional audited CryptoKit surface

| API / namespace | Status | Reason |
| --- | --- | --- |
| `AES.CBC` in CryptoKit proper | ⏭️ skipped | No public `CryptoKit` CBC API is exposed on macOS; crate provides a compatibility bridge instead. |
| `NIST` top-level namespace | ⏭️ skipped | No standalone `NIST` namespace is exposed in CryptoKit; the crate models NIST coverage through the P-256 / P-384 / P-521 modules and `nist` helpers. |
| `SecureEnclave` authentication context / access control customization | ✅ | Access control is `security-rs`'s `AccessControl` (re-exported from `secure_enclave`), authentication contexts are `SecureEnclaveAuthenticationContext`, and both feed the option-aware Secure Enclave create/restore flows. |
