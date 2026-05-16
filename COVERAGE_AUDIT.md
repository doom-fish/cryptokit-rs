# cryptokit-rs coverage audit (vs MacOSX26.2.sdk)

SDK_PUBLIC_SYMBOLS: 55
VERIFIED: 31
GAPS: 24
EXEMPT: 0
COVERAGE_PCT: 56.36%

Audited SDK source: `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.2.sdk/System/Library/Frameworks/CryptoKit.framework/Versions/A/Modules/CryptoKit.swiftmodule/x86_64-apple-macos.swiftinterface`

Methodology: audited the public macOS `CryptoKit` surface from the swiftinterface and mapped it to `cryptokit-rs` public Rust APIs plus `swift-bridge` thunks. To keep the report readable, overload sets and protocol-conformance boilerplate (`==`, `hash(into:)`, `hashValue`, `description`, `allCases`, `Element`, `Iterator`) are collapsed into symbol families. macOS-unavailable declarations were filtered out. No deprecated macOS declarations were present, so `EXEMPT = 0`. `AesCbc` is intentionally excluded because CryptoKit exposes no public CBC API on macOS.

## 🟢 VERIFIED
| Symbol | Kind | Header | Wrapped by |
| --- | --- | --- | --- |
| `SymmetricKey.init(size:) / init(data:) / bitCount` | struct + inits/var family | `CryptoKit.swiftinterface` | `symmetric::SymmetricKey` |
| `SymmetricKeySize.bits128/bits192/bits256` | struct + var family | `CryptoKit.swiftinterface` | `symmetric::SymmetricKeySize`, `symmetric_key::supported_sizes` |
| `AES` | enum namespace | `CryptoKit.swiftinterface` | `symmetric::AesGcm`, `aes_gcm::AesGcm` |
| `AES.GCM.seal/open` | func family | `CryptoKit.swiftinterface` | `symmetric::AesGcm`, `aes_gcm::AesGcm` |
| `AES.GCM.SealedBox.{combined,nonce,ciphertext,tag}` | struct + var family | `CryptoKit.swiftinterface` | `aes_gcm::AesGcmSealedBox` |
| `ChaChaPoly.seal/open` | func family | `CryptoKit.swiftinterface` | `symmetric::ChaCha20Poly1305`, `chacha_poly::ChaChaPoly` |
| `ChaChaPoly.SealedBox.{combined,nonce,ciphertext,tag}` | struct + var family | `CryptoKit.swiftinterface` | `chacha_poly::ChaChaPolySealedBox` |
| `SharedSecret.hkdfDerivedSymmetricKey / x963DerivedSymmetricKey` | struct + func family | `CryptoKit.swiftinterface` | `public_key::SharedSecret`, `key_derivation::{derive_hkdf, derive_x963, derive}` |
| `HKDF.deriveKey` | func family | `CryptoKit.swiftinterface` | `hkdf::{hkdf, hkdf_sha256, hkdf_sha384, hkdf_sha512}`, `key_derivation::derive_hkdf` |
| `HMAC.authenticationCode` | func family | `CryptoKit.swiftinterface` | `hmac::{hmac, hmac_sha256, hmac_sha384, hmac_sha512}` |
| `Insecure` | enum namespace | `CryptoKit.swiftinterface` | `insecure` module |
| `Insecure.SHA1` | struct family | `CryptoKit.swiftinterface` | `insecure::sha1` |
| `Insecure.MD5` | struct family | `CryptoKit.swiftinterface` | `insecure::md5` |
| `SHA256.hash` | func family | `CryptoKit.swiftinterface` | `sha::sha256`, `hashing::sha256` |
| `SHA384.hash` | func family | `CryptoKit.swiftinterface` | `sha::sha384`, `hashing::sha384` |
| `SHA512.hash` | func family | `CryptoKit.swiftinterface` | `sha::sha512`, `hashing::sha512` |
| `Curve25519` | enum namespace | `CryptoKit.swiftinterface` | `curve25519` module, `public_key` generic wrappers |
| `Curve25519.Signing.{PrivateKey,PublicKey,signature,isValidSignature,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `curve25519::{Ed25519PrivateKey, Ed25519PublicKey}`, `public_key::{SigningPrivateKey, SigningPublicKey}` |
| `Curve25519.KeyAgreement.{PrivateKey,PublicKey,sharedSecretFromKeyAgreement,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `curve25519::{X25519PrivateKey, X25519PublicKey}`, `public_key::{KeyAgreementPrivateKey, KeyAgreementPublicKey}` |
| `P256` | enum namespace | `CryptoKit.swiftinterface` | `p256` module, `public_key` generic wrappers |
| `P256.Signing.{PrivateKey,PublicKey,signature,isValidSignature,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `p256::{P256SigningPrivateKey, P256SigningPublicKey}`, `public_key::{SigningPrivateKey, SigningPublicKey}` |
| `P256.KeyAgreement.{PrivateKey,PublicKey,sharedSecretFromKeyAgreement,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `p256::{P256KeyAgreementPrivateKey, P256KeyAgreementPublicKey}`, `public_key::{KeyAgreementPrivateKey, KeyAgreementPublicKey}` |
| `P384` | enum namespace | `CryptoKit.swiftinterface` | `p384` module, `public_key` generic wrappers |
| `P384.Signing.{PrivateKey,PublicKey,signature,isValidSignature,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `p384::{P384SigningPrivateKey, P384SigningPublicKey}`, `public_key::{SigningPrivateKey, SigningPublicKey}` |
| `P384.KeyAgreement.{PrivateKey,PublicKey,sharedSecretFromKeyAgreement,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `p384::{P384KeyAgreementPrivateKey, P384KeyAgreementPublicKey}`, `public_key::{KeyAgreementPrivateKey, KeyAgreementPublicKey}` |
| `P521` | enum namespace | `CryptoKit.swiftinterface` | `p521` module, `public_key` generic wrappers |
| `P521.Signing.{PrivateKey,PublicKey,signature,isValidSignature,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `p521::{P521SigningPrivateKey, P521SigningPublicKey}`, `public_key::{SigningPrivateKey, SigningPublicKey}` |
| `P521.KeyAgreement.{PrivateKey,PublicKey,sharedSecretFromKeyAgreement,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `p521::{P521KeyAgreementPrivateKey, P521KeyAgreementPublicKey}`, `public_key::{KeyAgreementPrivateKey, KeyAgreementPublicKey}` |
| `SecureEnclave.isAvailable` | var family | `CryptoKit.swiftinterface` | `secure_enclave::is_available` |
| `SecureEnclave.P256.Signing.PrivateKey.{init,publicKey,signature(for: data)}` | struct + func family | `CryptoKit.swiftinterface` | `secure_enclave::SecureEnclaveSigningPrivateKey` |
| `SecureEnclave.P256.KeyAgreement.PrivateKey.{init,publicKey,sharedSecretFromKeyAgreement}` | struct + func family | `CryptoKit.swiftinterface` | `secure_enclave::SecureEnclaveKeyAgreementPrivateKey` |

## 🔴 GAPS
| Symbol | Kind | Header | Notes |
| --- | --- | --- | --- |
| `AES.KeyWrap` | enum + func family | `CryptoKit.swiftinterface` | No Rust `key_wrap` module or bridge thunks. |
| `AES.GCM.Nonce` | struct family | `CryptoKit.swiftinterface` | Callers pass raw `&[u8]`; there is no dedicated nonce type or constructor. |
| `ChaChaPoly.Nonce` | struct family | `CryptoKit.swiftinterface` | Callers pass raw `&[u8]`; there is no dedicated nonce type or constructor. |
| `Digest + SHA256/SHA384/SHA512/SHA1/MD5 digest result types` | protocol + struct family | `CryptoKit.swiftinterface` | Rust returns `Vec<u8>` instead of typed digest values. |
| `HashFunction.init/update/finalize` | protocol + func family | `CryptoKit.swiftinterface` | No streaming hash state or trait equivalent; only one-shot helpers are exposed. |
| `MessageAuthenticationCode + HashedAuthenticationCode` | protocol + struct family | `CryptoKit.swiftinterface` | No typed MAC values are exposed; Rust returns raw bytes. |
| `SHA2_256 / SHA2_384 / SHA2_512` | typealias family | `CryptoKit.swiftinterface` | The new 26.0 alias names are not mirrored in Rust. |
| `CryptoKitError` | enum | `CryptoKit.swiftinterface` | `error::CryptoKitError` is a crate-defined status mapping, not the Swift enum surface. |
| `CryptoKitASN1Error / CryptoKitMetaError / CorecryptoCurveType` | enum/typealias/struct family | `CryptoKit.swiftinterface` | No ASN.1/meta/corecrypto utility types are exposed. |
| `Curve25519.KeyAgreement.PublicKey.init(_:kem:) / hpkeRepresentation(kem:)` | init + func family | `CryptoKit.swiftinterface` | No HPKE serialization helpers are exposed on curve public keys. |
| `P256.Signing.ECDSASignature` | struct family | `CryptoKit.swiftinterface` | Signatures are passed as raw bytes; typed ECDSA signature wrappers are absent. |
| `P384.Signing.ECDSASignature` | struct family | `CryptoKit.swiftinterface` | Signatures are passed as raw bytes; typed ECDSA signature wrappers are absent. |
| `P521.Signing.ECDSASignature` | struct family | `CryptoKit.swiftinterface` | Signatures are passed as raw bytes; typed ECDSA signature wrappers are absent. |
| `P256/P384/P521 compact/x963/compressed/pem/der representations` | init + var family | `CryptoKit.swiftinterface` | The crate validates and exports raw representations only; alternate encodings are not wrapped. |
| `SecureEnclave.P256.*.dataRepresentation + restore/authenticationContext/accessControl` | var + init family | `CryptoKit.swiftinterface` | Only generation/use is exposed; persistent key restore and auth-context customization are missing. |
| `HKDF.extract / HKDF.expand` | func family | `CryptoKit.swiftinterface` | Only `deriveKey` flows are reachable from Rust. |
| `HMAC.init/update/finalize + isValidAuthenticationCode` | struct + func family | `CryptoKit.swiftinterface` | No streaming HMAC state or verification helpers are exposed. |
| `DiffieHellmanKeyAgreement` | protocol | `CryptoKit.swiftinterface` | No Rust trait mirrors the Swift protocol; only concrete wrappers exist. |
| `HPKE.{KDF,AEAD,KEM,Ciphersuite,Sender,Recipient,Errors,DHKEM}` | namespace family | `CryptoKit.swiftinterface` | No `hpke` module, bridge, or public Rust types exist. |
| `HPKE{PublicKeySerialization,DiffieHellmanPublicKey,DiffieHellmanPrivateKey,DiffieHellmanPrivateKeyGeneration,KEMPublicKey,KEMPrivateKey,KEMPrivateKeyGeneration}` | protocol family | `CryptoKit.swiftinterface` | No Rust HPKE protocol surface or bridge support exists. |
| `KEM.{EncapsulationResult,Errors} + KEMPublicKey/KEMPrivateKey` | namespace + protocol family | `CryptoKit.swiftinterface` | No encapsulation/decapsulation API or public KEM key types are exposed. |
| `SHA3_{256,384,512} + SHA3 digest types` | struct family | `CryptoKit.swiftinterface` | No SHA3 bridge or Rust API exists. |
| `MLKEM768 / MLKEM1024 / MLDSA65 / MLDSA87 / XWingMLKEM768X25519` | namespace family | `CryptoKit.swiftinterface` | No software post-quantum or hybrid key APIs are exposed. |
| `SecureEnclave.{MLKEM768,MLKEM1024,MLDSA65,MLDSA87}` | namespace family | `CryptoKit.swiftinterface` | No Secure Enclave post-quantum bindings are exposed. |

## ⏭️ EXEMPT

No deprecated macOS declarations were present in `CryptoKit.swiftinterface`, so `EXEMPT = 0`.
