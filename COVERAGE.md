# CryptoKit coverage audit

Audited against the macOS CryptoKit surface available on this machine, with the crate organized by logical area.

Legend:

- ✅ implemented
- 🟡 partial
- ⏭️ skipped

## Logical areas requested for v0.2.0

| Area | Swift bridge | Rust module | Status | Notes |
| --- | --- | --- | --- | --- |
| SymmetricKey | `Symmetric.swift`, `SymmetricKey.swift` | `src/symmetric_key.rs` | ✅ | Generates 128/192/256-bit keys and reports supported sizes. |
| AESGCM | `Symmetric.swift`, `AESGCM.swift` | `src/aes_gcm.rs` | ✅ | Combined sealed boxes, nonce/ciphertext/tag accessors, explicit nonce support, and authenticated data. |
| AESCBC | `AESCBC.swift` | `src/aes_cbc.rs` | ✅ | PKCS#7 CBC interoperability via Swift/CommonCrypto because CryptoKit itself does not expose CBC mode on macOS. |
| ChaChaPoly | `Symmetric.swift`, `ChaChaPoly.swift` | `src/chacha_poly.rs` | ✅ | Combined sealed boxes plus authenticated-data support. |
| P256 | `PublicKey.swift`, `P256.swift` | `src/p256.rs` | ✅ | Signing, verification, key agreement, raw import/export, and curve-specific wrappers. |
| P384 | `PublicKey.swift`, `P384.swift` | `src/p384.rs` | ✅ | Signing, verification, key agreement, raw import/export, and curve-specific wrappers. |
| P521 | `PublicKey.swift`, `P521.swift` | `src/p521.rs` | ✅ | Signing, verification, key agreement, raw import/export, and curve-specific wrappers. |
| Curve25519 | `PublicKey.swift`, `Curve25519.swift` | `src/curve25519.rs` | ✅ | Ed25519 signing/verification plus X25519 key agreement wrappers. |
| HKDF | `HKDF.swift` | `src/hkdf.rs` | ✅ | HKDF-SHA256 / SHA384 / SHA512 over symmetric key material. |
| HMAC | `HMAC.swift` | `src/hmac.rs` | ✅ | HMAC-SHA256 / SHA384 / SHA512. |
| SHA | `Hashing.swift`, `SHA.swift` | `src/sha.rs` | ✅ | SHA-256 / SHA-384 / SHA-512 helpers. |
| SecureEnclave | `SecureEnclave.swift` | `src/secure_enclave.rs` | 🟡 | Availability probe plus P-256 signing/key-agreement handles are wrapped; persistent key restoration and authentication-context customization are not yet exposed. |
| NIST | `NIST.swift` | `src/nist.rs` | ✅ | P-256 / P-384 / P-521 discovery and generic helper APIs. |
| Insecure (MD5/SHA1) | `Hashing.swift`, `Insecure.swift` | `src/insecure.rs` | ✅ | `Insecure.MD5` and `Insecure.SHA1`. |
| KeyAgreement | `KeyAgreement.swift`, `PublicKey.swift` | `src/key_agreement.rs` | ✅ | Generic P-256 / P-384 / P-521 / X25519 key-agreement wrappers and support discovery. |
| KeyDerivation | `KeyDerivation.swift` | `src/key_derivation.rs` | ✅ | Shared-secret HKDF plus ANSI X9.63 derivation with SHA-256 / SHA-384 / SHA-512. |

## Additional audited CryptoKit surface

| API / namespace | Status | Reason |
| --- | --- | --- |
| `AES.KeyWrap` | ⏭️ skipped | Separate API surface from the requested logical areas. |
| `AES.CBC` in CryptoKit proper | ⏭️ skipped | No public `CryptoKit` CBC API is exposed on macOS; crate provides a compatibility bridge instead. |
| `NIST` top-level namespace | ⏭️ skipped | No standalone `NIST` namespace is exposed in CryptoKit; the crate models NIST coverage through the P-256 / P-384 / P-521 modules and `nist` helpers. |
| `SecureEnclave` persistent `dataRepresentation` restore flows | 🟡 partial | Generation, signing, agreement, and public-key export are wrapped; restore/import flows are still deferred. |
| `SHA3_*`, HPKE/KEM, and ML-KEM additions from newer SDKs | ⏭️ skipped | Newer macOS 26-era APIs are outside the crate's current 10.15 baseline and user-requested scope. |
