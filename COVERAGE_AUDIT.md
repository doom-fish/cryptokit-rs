# cryptokit-rs coverage audit (vs MacOSX26.2.sdk)

SDK_PUBLIC_SYMBOLS: 56
VERIFIED: 44
GAPS: 12
EXEMPT: 0
COVERAGE_PCT: 78.57%

Audited SDK source: `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.2.sdk/System/Library/Frameworks/CryptoKit.framework/Versions/A/Modules/CryptoKit.swiftmodule/x86_64-apple-macos.swiftinterface`

Methodology: audited the public macOS `CryptoKit` surface from the swiftinterface and mapped it to `cryptokit-rs` public Rust APIs plus `swift-bridge` thunks. To keep the report readable, overload sets and protocol-conformance boilerplate (`==`, `hash(into:)`, `hashValue`, `description`, `allCases`, `Element`, `Iterator`) are collapsed into symbol families. macOS-unavailable declarations were filtered out. No deprecated macOS declarations were present, so `EXEMPT = 0`. `AesCbc` is intentionally excluded because CryptoKit exposes no public CBC API on macOS. Secure Enclave `dataRepresentation`/restore flows are tracked separately from `authenticationContext`/`accessControl` customization so the remaining gap matches the unwrapped surface.

## 🟢 VERIFIED
| Symbol | Kind | Header | Wrapped by |
| --- | --- | --- | --- |
| `SymmetricKey.init(size:) / init(data:) / bitCount` | struct + inits/var family | `CryptoKit.swiftinterface` | `symmetric::SymmetricKey` |
| `SymmetricKeySize.bits128/bits192/bits256` | struct + var family | `CryptoKit.swiftinterface` | `symmetric::SymmetricKeySize`, `symmetric_key::supported_sizes` |
| `AES` | enum namespace | `CryptoKit.swiftinterface` | `symmetric::AesGcm`, `aes_gcm::AesGcm` |
| `AES.GCM.seal/open` | func family | `CryptoKit.swiftinterface` | `symmetric::AesGcm`, `aes_gcm::AesGcm` |
| `AES.GCM.SealedBox.{combined,nonce,ciphertext,tag}` | struct + var family | `CryptoKit.swiftinterface` | `aes_gcm::AesGcmSealedBox` |
| `AES.KeyWrap` | enum + func family | `CryptoKit.swiftinterface` | `key_wrap::{AesKeyWrap, wrap, unwrap}` |
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
| `SHA3_{256,384,512} + SHA3 digest types` | struct family | `CryptoKit.swiftinterface` | `sha3::{sha3_256, sha3_384, sha3_512, Sha3_256, Sha3_384, Sha3_512, Sha3_256Digest, Sha3_384Digest, Sha3_512Digest}` |
| `Curve25519` | enum namespace | `CryptoKit.swiftinterface` | `curve25519` module, `public_key` generic wrappers |
| `Curve25519.Signing.{PrivateKey,PublicKey,signature,isValidSignature,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `curve25519::{Ed25519PrivateKey, Ed25519PublicKey}`, `public_key::{SigningPrivateKey, SigningPublicKey}` |
| `Curve25519.KeyAgreement.{PrivateKey,PublicKey,sharedSecretFromKeyAgreement,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `curve25519::{X25519PrivateKey, X25519PublicKey}`, `public_key::{KeyAgreementPrivateKey, KeyAgreementPublicKey}` |
| `Curve25519/P256/P384/P521.KeyAgreement.PublicKey.init(_:kem:) / hpkeRepresentation(kem:)` | init + func family | `CryptoKit.swiftinterface` | `hpke::HpkePublicKeySerialization` impls on `X25519PublicKey`, `P256KeyAgreementPublicKey`, `P384KeyAgreementPublicKey`, and `P521KeyAgreementPublicKey` |
| `P256` | enum namespace | `CryptoKit.swiftinterface` | `p256` module, `public_key` generic wrappers |
| `P256.Signing.{PrivateKey,PublicKey,signature,isValidSignature,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `p256::{P256SigningPrivateKey, P256SigningPublicKey}`, `public_key::{SigningPrivateKey, SigningPublicKey}` |
| `P256.Signing.ECDSASignature` | struct family | `CryptoKit.swiftinterface` | `p256::P256EcdsaSignature` |
| `P256.KeyAgreement.{PrivateKey,PublicKey,sharedSecretFromKeyAgreement,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `p256::{P256KeyAgreementPrivateKey, P256KeyAgreementPublicKey}`, `public_key::{KeyAgreementPrivateKey, KeyAgreementPublicKey}` |
| `P384` | enum namespace | `CryptoKit.swiftinterface` | `p384` module, `public_key` generic wrappers |
| `P384.Signing.{PrivateKey,PublicKey,signature,isValidSignature,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `p384::{P384SigningPrivateKey, P384SigningPublicKey}`, `public_key::{SigningPrivateKey, SigningPublicKey}` |
| `P384.Signing.ECDSASignature` | struct family | `CryptoKit.swiftinterface` | `p384::P384EcdsaSignature` |
| `P384.KeyAgreement.{PrivateKey,PublicKey,sharedSecretFromKeyAgreement,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `p384::{P384KeyAgreementPrivateKey, P384KeyAgreementPublicKey}`, `public_key::{KeyAgreementPrivateKey, KeyAgreementPublicKey}` |
| `P521` | enum namespace | `CryptoKit.swiftinterface` | `p521` module, `public_key` generic wrappers |
| `P521.Signing.{PrivateKey,PublicKey,signature,isValidSignature,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `p521::{P521SigningPrivateKey, P521SigningPublicKey}`, `public_key::{SigningPrivateKey, SigningPublicKey}` |
| `P521.Signing.ECDSASignature` | struct family | `CryptoKit.swiftinterface` | `p521::P521EcdsaSignature` |
| `P521.KeyAgreement.{PrivateKey,PublicKey,sharedSecretFromKeyAgreement,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `p521::{P521KeyAgreementPrivateKey, P521KeyAgreementPublicKey}`, `public_key::{KeyAgreementPrivateKey, KeyAgreementPublicKey}` |
| `SecureEnclave.isAvailable` | var family | `CryptoKit.swiftinterface` | `secure_enclave::is_available` |
| `SecureEnclave.P256.Signing.PrivateKey.{init,publicKey,signature(for: data)}` | struct + func family | `CryptoKit.swiftinterface` | `secure_enclave::SecureEnclaveSigningPrivateKey` |
| `SecureEnclave.P256.KeyAgreement.PrivateKey.{init,publicKey,sharedSecretFromKeyAgreement}` | struct + func family | `CryptoKit.swiftinterface` | `secure_enclave::SecureEnclaveKeyAgreementPrivateKey` |
| `SecureEnclave.P256.*.dataRepresentation + restore` | var + init family | `CryptoKit.swiftinterface` | `secure_enclave::{SecureEnclaveSigningPrivateKey, SecureEnclaveKeyAgreementPrivateKey}` |
| `DiffieHellmanKeyAgreement` | protocol | `CryptoKit.swiftinterface` | `key_agreement::DiffieHellmanKeyAgreement` with P-256 / P-384 / P-521 / X25519 impls |
| `HPKE.{KDF,AEAD,KEM,Ciphersuite,Sender,Recipient,Errors,DHKEM}` | namespace family | `CryptoKit.swiftinterface` | `hpke::{HpkeKdf, HpkeAead, HpkeKem, HpkeCiphersuite, HpkeError, Dhkem, Sender, Recipient}` |
| `HPKE{PublicKeySerialization,DiffieHellmanPublicKey,DiffieHellmanPrivateKey,DiffieHellmanPrivateKeyGeneration,KEMPublicKey,KEMPrivateKey,KEMPrivateKeyGeneration}` | protocol family | `CryptoKit.swiftinterface` | `hpke::{HpkePublicKeySerialization, HpkeDiffieHellmanPublicKey, HpkeDiffieHellmanPrivateKey, HpkeDiffieHellmanPrivateKeyGeneration, HpkeKemPublicKey, HpkeKemPrivateKey, HpkeKemPrivateKeyGeneration}` |
| `KEM.{EncapsulationResult,Errors} + KEMPublicKey/KEMPrivateKey` | namespace + protocol family | `CryptoKit.swiftinterface` | `kem::{EncapsulationResult, KemPublicKey, KemPrivateKey}` |
| `MLKEM768 / MLKEM1024 / MLDSA65 / MLDSA87 / XWingMLKEM768X25519` | namespace family | `CryptoKit.swiftinterface` | `kem::{Mlkem768PrivateKey, Mlkem768PublicKey, Mlkem1024PrivateKey, Mlkem1024PublicKey, XWingMlkem768X25519PrivateKey, XWingMlkem768X25519PublicKey}`, `mldsa::{Mldsa65PrivateKey, Mldsa65PublicKey, Mldsa87PrivateKey, Mldsa87PublicKey}` |
| `SecureEnclave.{MLKEM768,MLKEM1024,MLDSA65,MLDSA87}` | namespace family | `CryptoKit.swiftinterface` | `secure_enclave::{SecureEnclaveMlkem768PrivateKey, SecureEnclaveMlkem1024PrivateKey, SecureEnclaveMldsa65PrivateKey, SecureEnclaveMldsa87PrivateKey}` |

## 🔴 GAPS
| Symbol | Kind | Header | Notes |
| --- | --- | --- | --- |
| `AES.GCM.Nonce` | struct family | `CryptoKit.swiftinterface` | Callers pass raw `&[u8]`; there is no dedicated nonce type or constructor. |
| `ChaChaPoly.Nonce` | struct family | `CryptoKit.swiftinterface` | Callers pass raw `&[u8]`; there is no dedicated nonce type or constructor. |
| `Digest + SHA256/SHA384/SHA512/SHA1/MD5 digest result types` | protocol + struct family | `CryptoKit.swiftinterface` | Rust returns `Vec<u8>` for SHA-2 / insecure hashes instead of typed digest values. |
| `HashFunction.init/update/finalize` | protocol + func family | `CryptoKit.swiftinterface` | No streaming hash state or trait equivalent exists for the SHA-2 / insecure hash families. |
| `MessageAuthenticationCode + HashedAuthenticationCode` | protocol + struct family | `CryptoKit.swiftinterface` | No typed MAC values are exposed; Rust returns raw bytes. |
| `SHA2_256 / SHA2_384 / SHA2_512` | typealias family | `CryptoKit.swiftinterface` | The new 26.0 alias names are not mirrored in Rust. |
| `CryptoKitError` | enum | `CryptoKit.swiftinterface` | `error::CryptoKitError` is a crate-defined status mapping, not the Swift enum surface. |
| `CryptoKitASN1Error / CryptoKitMetaError / CorecryptoCurveType` | enum/typealias/struct family | `CryptoKit.swiftinterface` | No ASN.1/meta/corecrypto utility types are exposed. |
| `P256/P384/P521 compact/x963/compressed/pem/der representations` | init + var family | `CryptoKit.swiftinterface` | The crate validates and exports raw representations only; alternate encodings are not wrapped. |
| `SecureEnclave.P256.*.authenticationContext / accessControl` | var + init family | `CryptoKit.swiftinterface` | `dataRepresentation` export/restore is wrapped, but authentication-context and access-control customization remain missing. |
| `HKDF.extract / HKDF.expand` | func family | `CryptoKit.swiftinterface` | Only `deriveKey` flows are reachable from Rust. |
| `HMAC.init/update/finalize + isValidAuthenticationCode` | struct + func family | `CryptoKit.swiftinterface` | No streaming HMAC state or verification helpers are exposed. |

## ⏭️ EXEMPT

No deprecated macOS declarations were present in `CryptoKit.swiftinterface`, so `EXEMPT = 0`.
