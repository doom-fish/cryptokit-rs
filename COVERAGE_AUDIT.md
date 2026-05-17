# cryptokit-rs coverage audit (vs MacOSX26.2.sdk)

SDK_PUBLIC_SYMBOLS: 56
VERIFIED: 54
GAPS: 0
EXEMPT: 2
COVERAGE_PCT: 100.00%

Audited SDK source: `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.2.sdk/System/Library/Frameworks/CryptoKit.framework/Versions/A/Modules/CryptoKit.swiftmodule/x86_64-apple-macos.swiftinterface`

Methodology: audited the public macOS `CryptoKit` surface from the swiftinterface and mapped it to `cryptokit-rs` public Rust APIs plus `swift-bridge` thunks. To keep the report readable, overload sets and protocol-conformance boilerplate (`==`, `hash(into:)`, `hashValue`, `description`, `allCases`, `Element`, `Iterator`) are collapsed into symbol families. macOS-unavailable declarations were filtered out. `AesCbc` is intentionally excluded because CryptoKit exposes no public CBC API on macOS. Swift-only error/meta utility families that are semantically covered by the crate's own error mapping (`CryptoKitError`) or are not independently actionable in Rust (`CryptoKitASN1Error / CryptoKitMetaError / CorecryptoCurveType`) are counted as `EXEMPT`; the remaining functional API surface is now fully wrapped.

## 🟢 VERIFIED
| Symbol | Kind | Header | Wrapped by |
| --- | --- | --- | --- |
| `SymmetricKey.init(size:) / init(data:) / bitCount` | struct + inits/var family | `CryptoKit.swiftinterface` | `symmetric::SymmetricKey` |
| `SymmetricKeySize.bits128/bits192/bits256` | struct + var family | `CryptoKit.swiftinterface` | `symmetric::SymmetricKeySize`, `symmetric_key::supported_sizes` |
| `AES` | enum namespace | `CryptoKit.swiftinterface` | `symmetric::AesGcm`, `aes_gcm::AesGcm` |
| `AES.GCM.seal/open` | func family | `CryptoKit.swiftinterface` | `symmetric::AesGcm`, `aes_gcm::AesGcm` |
| `AES.GCM.SealedBox.{combined,nonce,ciphertext,tag}` | struct + var family | `CryptoKit.swiftinterface` | `aes_gcm::AesGcmSealedBox` |
| `AES.GCM.Nonce` | struct family | `CryptoKit.swiftinterface` | `aes_gcm::AesGcmNonce` |
| `AES.KeyWrap` | enum + func family | `CryptoKit.swiftinterface` | `key_wrap::{AesKeyWrap, wrap, unwrap}` |
| `ChaChaPoly.seal/open` | func family | `CryptoKit.swiftinterface` | `symmetric::ChaCha20Poly1305`, `chacha_poly::ChaChaPoly` |
| `ChaChaPoly.SealedBox.{combined,nonce,ciphertext,tag}` | struct + var family | `CryptoKit.swiftinterface` | `chacha_poly::ChaChaPolySealedBox` |
| `ChaChaPoly.Nonce` | struct family | `CryptoKit.swiftinterface` | `chacha_poly::ChaChaPolyNonce` |
| `SharedSecret.hkdfDerivedSymmetricKey / x963DerivedSymmetricKey` | struct + func family | `CryptoKit.swiftinterface` | `public_key::SharedSecret`, `key_derivation::{derive_hkdf, derive_x963, derive}` |
| `HKDF.{deriveKey,extract,expand}` | func family | `CryptoKit.swiftinterface` | `hkdf::{hkdf, extract, expand, hkdf_sha256, hkdf_sha384, hkdf_sha512, hkdf_extract_sha256, hkdf_extract_sha384, hkdf_extract_sha512, hkdf_expand_sha256, hkdf_expand_sha384, hkdf_expand_sha512}`, `key_derivation::derive_hkdf` |
| `HMAC.init/update/finalize/authenticationCode/isValidAuthenticationCode` | struct + func family | `CryptoKit.swiftinterface` | `hmac::{Hmac, HmacSha256, HmacSha384, HmacSha512, HashedAuthenticationCode, hmac, hmac_typed, hmac_sha256, hmac_sha256_code, hmac_sha384, hmac_sha384_code, hmac_sha512, hmac_sha512_code, is_valid_authentication_code, is_valid_hmac_sha256, is_valid_hmac_sha384, is_valid_hmac_sha512}` |
| `Insecure` | enum namespace | `CryptoKit.swiftinterface` | `insecure` module |
| `Insecure.SHA1` | struct family | `CryptoKit.swiftinterface` | `insecure::{Sha1, Sha1Digest, sha1, sha1_digest}` |
| `Insecure.MD5` | struct family | `CryptoKit.swiftinterface` | `insecure::{Md5, Md5Digest, md5, md5_digest}` |
| `Digest + HashFunction + SHA256/SHA384/SHA512/SHA1/MD5 digest/result types` | protocol + struct family | `CryptoKit.swiftinterface` | `sha::{Digest, HashFunction, Sha256, Sha384, Sha512, Sha256Digest, Sha384Digest, Sha512Digest, SHA2_256, SHA2_384, SHA2_512}`, `insecure::{InsecureHashFunction, Md5, Sha1, Md5Digest, Sha1Digest}` |
| `SHA3_{256,384,512} + SHA3 digest types` | struct family | `CryptoKit.swiftinterface` | `sha3::{sha3_256, sha3_384, sha3_512, Sha3_256, Sha3_384, Sha3_512, Sha3_256Digest, Sha3_384Digest, Sha3_512Digest}` |
| `Curve25519` | enum namespace | `CryptoKit.swiftinterface` | `curve25519` module, `public_key` generic wrappers |
| `Curve25519.Signing.{PrivateKey,PublicKey,signature,isValidSignature,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `curve25519::{Ed25519PrivateKey, Ed25519PublicKey}`, `public_key::{SigningPrivateKey, SigningPublicKey}` |
| `Curve25519.KeyAgreement.{PrivateKey,PublicKey,sharedSecretFromKeyAgreement,rawRepresentation}` | namespace family | `CryptoKit.swiftinterface` | `curve25519::{X25519PrivateKey, X25519PublicKey}`, `public_key::{KeyAgreementPrivateKey, KeyAgreementPublicKey}` |
| `P256/P384/P521 compact/x963/compressed/pem/der representations` | init + var family | `CryptoKit.swiftinterface` | `public_key::{SigningPrivateKey, SigningPublicKey, KeyAgreementPrivateKey, KeyAgreementPublicKey}`, `p256`, `p384`, and `p521` typed wrappers |
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
| `SecureEnclave.P256.*.{dataRepresentation,compactRepresentable,authenticationContext,accessControl}` | var + init family | `CryptoKit.swiftinterface` | `secure_enclave::{SecureEnclaveSigningPrivateKey, SecureEnclaveKeyAgreementPrivateKey, SecureEnclaveAuthenticationContext, SecureEnclaveAccessControl, SecureEnclaveAccessControlFlags, SecureEnclaveAccessibility}` |
| `DiffieHellmanKeyAgreement` | protocol | `CryptoKit.swiftinterface` | `key_agreement::DiffieHellmanKeyAgreement` with P-256 / P-384 / P-521 / X25519 impls |
| `HPKE.{KDF,AEAD,KEM,Ciphersuite,Sender,Recipient,Errors,DHKEM}` | namespace family | `CryptoKit.swiftinterface` | `hpke::{HpkeKdf, HpkeAead, HpkeKem, HpkeCiphersuite, HpkeError, Dhkem, Sender, Recipient}` |
| `HPKE{PublicKeySerialization,DiffieHellmanPublicKey,DiffieHellmanPrivateKey,DiffieHellmanPrivateKeyGeneration,KEMPublicKey,KEMPrivateKey,KEMPrivateKeyGeneration}` | protocol family | `CryptoKit.swiftinterface` | `hpke::{HpkePublicKeySerialization, HpkeDiffieHellmanPublicKey, HpkeDiffieHellmanPrivateKey, HpkeDiffieHellmanPrivateKeyGeneration, HpkeKemPublicKey, HpkeKemPrivateKey, HpkeKemPrivateKeyGeneration}` |
| `KEM.{EncapsulationResult,Errors} + KEMPublicKey/KEMPrivateKey` | namespace + protocol family | `CryptoKit.swiftinterface` | `kem::{EncapsulationResult, KemPublicKey, KemPrivateKey}` |
| `MLKEM768 / MLKEM1024 / MLDSA65 / MLDSA87 / XWingMLKEM768X25519` | namespace family | `CryptoKit.swiftinterface` | `kem::{Mlkem768PrivateKey, Mlkem768PublicKey, Mlkem1024PrivateKey, Mlkem1024PublicKey, XWingMlkem768X25519PrivateKey, XWingMlkem768X25519PublicKey}`, `mldsa::{Mldsa65PrivateKey, Mldsa65PublicKey, Mldsa87PrivateKey, Mldsa87PublicKey}` |
| `SecureEnclave.{MLKEM768,MLKEM1024,MLDSA65,MLDSA87}` | namespace family | `CryptoKit.swiftinterface` | `secure_enclave::{SecureEnclaveMlkem768PrivateKey, SecureEnclaveMlkem1024PrivateKey, SecureEnclaveMldsa65PrivateKey, SecureEnclaveMldsa87PrivateKey}` |
| `SecureEnclave.{MLKEM768,MLKEM1024,MLDSA65,MLDSA87}.{authenticationContext,accessControl}` | init family | `CryptoKit.swiftinterface` | `secure_enclave::{SecureEnclaveMlkem768PrivateKey, SecureEnclaveMlkem1024PrivateKey, SecureEnclaveMldsa65PrivateKey, SecureEnclaveMldsa87PrivateKey, SecureEnclaveAuthenticationContext, SecureEnclaveAccessControl, SecureEnclaveAccessControlFlags, SecureEnclaveAccessibility}` |

## 🔴 GAPS

No remaining functional gaps were found in the audited public `CryptoKit` surface.

## ⏭️ EXEMPT

| Symbol | Kind | Header | Notes |
| --- | --- | --- | --- |
| `CryptoKitError` | enum | `CryptoKit.swiftinterface` | The crate already exposes a Rust-native `error::CryptoKitError` status mapping instead of mirroring Swift's throw-only enum cases verbatim. |
| `CryptoKitASN1Error / CryptoKitMetaError / CorecryptoCurveType` | enum/typealias/struct family | `CryptoKit.swiftinterface` | Swift-only ASN.1/meta/corecrypto utility families are not independently actionable in the Rust API and remain intentionally unmapped. |
