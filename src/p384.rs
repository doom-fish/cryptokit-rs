//! P384 curve-specific helpers.

use crate::error::Result;
use crate::ffi;
use crate::key_agreement::DiffieHellmanKeyAgreement;
use crate::private::bridge_bytes;
use crate::public_key::{
    KeyAgreementAlgorithm, KeyAgreementPrivateKey, KeyAgreementPublicKey, SharedSecret,
    SigningAlgorithm, SigningPrivateKey, SigningPublicKey,
};

/// Return whether the Swift bridge reports P384 support.
#[must_use]
pub fn is_supported() -> bool {
    unsafe { ffi::ck_p384_is_supported() != 0 }
}

/// A typed P-384 ECDSA signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct P384EcdsaSignature {
    raw: Vec<u8>,
}

impl P384EcdsaSignature {
    /// Validate and wrap a raw `CryptoKit` signature representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid P-384 signature.
    pub fn from_raw_representation(raw: impl Into<Vec<u8>>) -> Result<Self> {
        let raw = raw.into();
        let canonical = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_ecdsa_signature_validate(
                SigningAlgorithm::P384.as_ffi(),
                ffi::ecdsa_signature_format::RAW,
                raw.as_ptr(),
                raw.len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(Self { raw: canonical })
    }

    /// Validate and wrap a DER-encoded P-384 ECDSA signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid DER signature.
    pub fn from_der_representation(der: impl Into<Vec<u8>>) -> Result<Self> {
        let der = der.into();
        let raw = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_ecdsa_signature_validate(
                SigningAlgorithm::P384.as_ffi(),
                ffi::ecdsa_signature_format::DER,
                der.as_ptr(),
                der.len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(Self { raw })
    }

    /// Borrow the raw signature representation.
    #[must_use]
    pub fn raw_representation(&self) -> &[u8] {
        &self.raw
    }

    /// Consume the signature and return its raw representation.
    #[must_use]
    pub fn into_raw_representation(self) -> Vec<u8> {
        self.raw
    }

    /// Export the DER-encoded signature representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn der_representation(&self) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_ecdsa_signature_representation(
                SigningAlgorithm::P384.as_ffi(),
                self.raw.as_ptr(),
                self.raw.len(),
                ffi::ecdsa_signature_format::DER,
                out,
                out_len,
                error_out,
            )
        })
    }
}

/// A P384 signing private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P384SigningPrivateKey(SigningPrivateKey);

impl P384SigningPrivateKey {
    /// Generate a new P384 signing private key.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self> {
        Ok(Self(SigningPrivateKey::generate(SigningAlgorithm::P384)?))
    }

    /// Validate and wrap a raw private-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_raw_representation(raw: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(SigningPrivateKey::from_raw_representation(
            SigningAlgorithm::P384,
            raw,
        )?))
    }

    /// Borrow the raw private-key bytes.
    #[must_use]
    pub fn raw_representation(&self) -> &[u8] {
        self.0.raw_representation()
    }

    /// Consume the key and return its raw representation.
    #[must_use]
    pub fn into_raw_representation(self) -> Vec<u8> {
        self.0.into_raw_representation()
    }

    /// Derive the matching public key.
    ///
    /// # Errors
    ///
    /// Returns an error if public-key derivation fails.
    pub fn public_key(&self) -> Result<P384SigningPublicKey> {
        Ok(P384SigningPublicKey(self.0.public_key()?))
    }

    /// Sign a message with the private key.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.0.sign(message)
    }

    /// Sign a message and return a typed ECDSA signature.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_signature(&self, message: &[u8]) -> Result<P384EcdsaSignature> {
        P384EcdsaSignature::from_raw_representation(self.sign(message)?)
    }
}

/// A P384 signing public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P384SigningPublicKey(SigningPublicKey);

impl P384SigningPublicKey {
    /// Validate and wrap a raw public-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_raw_representation(raw: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(SigningPublicKey::from_raw_representation(
            SigningAlgorithm::P384,
            raw,
        )?))
    }

    /// Borrow the raw public-key bytes.
    #[must_use]
    pub fn raw_representation(&self) -> &[u8] {
        self.0.raw_representation()
    }

    /// Consume the key and return its raw representation.
    #[must_use]
    pub fn into_raw_representation(self) -> Vec<u8> {
        self.0.into_raw_representation()
    }

    /// Verify a signature.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails because the inputs are malformed.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        self.0.verify(message, signature)
    }

    /// Verify a typed ECDSA signature.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails because the inputs are malformed.
    pub fn verify_signature(&self, message: &[u8], signature: &P384EcdsaSignature) -> Result<bool> {
        self.0.verify(message, signature.raw_representation())
    }
}

/// A P384 key-agreement private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P384KeyAgreementPrivateKey(KeyAgreementPrivateKey);

impl P384KeyAgreementPrivateKey {
    /// Generate a new P384 key-agreement private key.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self> {
        Ok(Self(KeyAgreementPrivateKey::generate(
            KeyAgreementAlgorithm::P384,
        )?))
    }

    /// Validate and wrap a raw private-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_raw_representation(raw: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(KeyAgreementPrivateKey::from_raw_representation(
            KeyAgreementAlgorithm::P384,
            raw,
        )?))
    }

    /// Borrow the raw private-key bytes.
    #[must_use]
    pub fn raw_representation(&self) -> &[u8] {
        self.0.raw_representation()
    }

    /// Consume the key and return its raw representation.
    #[must_use]
    pub fn into_raw_representation(self) -> Vec<u8> {
        self.0.into_raw_representation()
    }

    /// Derive the matching public key.
    ///
    /// # Errors
    ///
    /// Returns an error if public-key derivation fails.
    pub fn public_key(&self) -> Result<P384KeyAgreementPublicKey> {
        Ok(P384KeyAgreementPublicKey(self.0.public_key()?))
    }

    /// Perform key agreement with a peer public key.
    ///
    /// # Errors
    ///
    /// Returns an error if key agreement fails.
    pub fn shared_secret(&self, peer: &P384KeyAgreementPublicKey) -> Result<SharedSecret> {
        self.0.shared_secret(&peer.0)
    }
}

/// A P384 key-agreement public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P384KeyAgreementPublicKey(KeyAgreementPublicKey);

impl DiffieHellmanKeyAgreement for P384KeyAgreementPrivateKey {
    type PublicKey = P384KeyAgreementPublicKey;

    fn public_key(&self) -> Result<Self::PublicKey> {
        Self::public_key(self)
    }

    fn shared_secret(&self, public_key: &Self::PublicKey) -> Result<SharedSecret> {
        Self::shared_secret(self, public_key)
    }
}

impl P384KeyAgreementPublicKey {
    /// Validate and wrap a raw public-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_raw_representation(raw: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(KeyAgreementPublicKey::from_raw_representation(
            KeyAgreementAlgorithm::P384,
            raw,
        )?))
    }

    /// Borrow the raw public-key bytes.
    #[must_use]
    pub fn raw_representation(&self) -> &[u8] {
        self.0.raw_representation()
    }

    /// Consume the key and return its raw representation.
    #[must_use]
    pub fn into_raw_representation(self) -> Vec<u8> {
        self.0.into_raw_representation()
    }
}

impl P384SigningPrivateKey {
    /// Generate a new private signing key with explicit compact-representation support.
    ///
    /// # Errors
    ///
    /// Returns an error if key creation fails.
    pub fn generate_with_compact_representable(compact_representable: bool) -> Result<Self> {
        Ok(Self(
            SigningPrivateKey::generate_with_compact_representable(
                SigningAlgorithm::P384,
                compact_representable,
            )?,
        ))
    }

    /// Validate and wrap an ANSI X9.63 private-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_x963_representation(x963: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(SigningPrivateKey::from_x963_representation(
            SigningAlgorithm::P384,
            x963,
        )?))
    }

    /// Export this private key in ANSI X9.63 form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn x963_representation(&self) -> Result<Vec<u8>> {
        self.0.x963_representation()
    }

    /// Validate and wrap a DER private-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_der_representation(der: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(SigningPrivateKey::from_der_representation(
            SigningAlgorithm::P384,
            der,
        )?))
    }

    /// Export this private key in DER form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn der_representation(&self) -> Result<Vec<u8>> {
        self.0.der_representation()
    }

    /// Validate and wrap a PEM private-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is invalid for P384.
    pub fn from_pem_representation(pem: impl AsRef<str>) -> Result<Self> {
        Ok(Self(SigningPrivateKey::from_pem_representation(
            SigningAlgorithm::P384,
            pem,
        )?))
    }

    /// Export this private key in PEM form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn pem_representation(&self) -> Result<String> {
        self.0.pem_representation()
    }
}

impl P384SigningPublicKey {
    /// Validate and wrap a compact public-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_compact_representation(compact: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(SigningPublicKey::from_compact_representation(
            SigningAlgorithm::P384,
            compact,
        )?))
    }

    /// Export this public key in compact form when one exists.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn compact_representation(&self) -> Result<Option<Vec<u8>>> {
        self.0.compact_representation()
    }

    /// Validate and wrap an ANSI X9.63 public-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_x963_representation(x963: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(SigningPublicKey::from_x963_representation(
            SigningAlgorithm::P384,
            x963,
        )?))
    }

    /// Export this public key in ANSI X9.63 form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn x963_representation(&self) -> Result<Vec<u8>> {
        self.0.x963_representation()
    }

    /// Validate and wrap a compressed public-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_compressed_representation(compressed: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(SigningPublicKey::from_compressed_representation(
            SigningAlgorithm::P384,
            compressed,
        )?))
    }

    /// Export this public key in compressed form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn compressed_representation(&self) -> Result<Vec<u8>> {
        self.0.compressed_representation()
    }

    /// Validate and wrap a DER public-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_der_representation(der: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(SigningPublicKey::from_der_representation(
            SigningAlgorithm::P384,
            der,
        )?))
    }

    /// Export this public key in DER form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn der_representation(&self) -> Result<Vec<u8>> {
        self.0.der_representation()
    }

    /// Validate and wrap a PEM public-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is invalid for P384.
    pub fn from_pem_representation(pem: impl AsRef<str>) -> Result<Self> {
        Ok(Self(SigningPublicKey::from_pem_representation(
            SigningAlgorithm::P384,
            pem,
        )?))
    }

    /// Export this public key in PEM form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn pem_representation(&self) -> Result<String> {
        self.0.pem_representation()
    }
}

impl P384KeyAgreementPrivateKey {
    /// Generate a new private key-agreement key with explicit compact-representation support.
    ///
    /// # Errors
    ///
    /// Returns an error if key creation fails.
    pub fn generate_with_compact_representable(compact_representable: bool) -> Result<Self> {
        Ok(Self(
            KeyAgreementPrivateKey::generate_with_compact_representable(
                KeyAgreementAlgorithm::P384,
                compact_representable,
            )?,
        ))
    }

    /// Validate and wrap an ANSI X9.63 private-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_x963_representation(x963: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(KeyAgreementPrivateKey::from_x963_representation(
            KeyAgreementAlgorithm::P384,
            x963,
        )?))
    }

    /// Export this private key in ANSI X9.63 form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn x963_representation(&self) -> Result<Vec<u8>> {
        self.0.x963_representation()
    }

    /// Validate and wrap a DER private-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_der_representation(der: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(KeyAgreementPrivateKey::from_der_representation(
            KeyAgreementAlgorithm::P384,
            der,
        )?))
    }

    /// Export this private key in DER form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn der_representation(&self) -> Result<Vec<u8>> {
        self.0.der_representation()
    }

    /// Validate and wrap a PEM private-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is invalid for P384.
    pub fn from_pem_representation(pem: impl AsRef<str>) -> Result<Self> {
        Ok(Self(KeyAgreementPrivateKey::from_pem_representation(
            KeyAgreementAlgorithm::P384,
            pem,
        )?))
    }

    /// Export this private key in PEM form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn pem_representation(&self) -> Result<String> {
        self.0.pem_representation()
    }
}

impl P384KeyAgreementPublicKey {
    /// Validate and wrap a compact public-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_compact_representation(compact: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(KeyAgreementPublicKey::from_compact_representation(
            KeyAgreementAlgorithm::P384,
            compact,
        )?))
    }

    /// Export this public key in compact form when one exists.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn compact_representation(&self) -> Result<Option<Vec<u8>>> {
        self.0.compact_representation()
    }

    /// Validate and wrap an ANSI X9.63 public-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_x963_representation(x963: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(KeyAgreementPublicKey::from_x963_representation(
            KeyAgreementAlgorithm::P384,
            x963,
        )?))
    }

    /// Export this public key in ANSI X9.63 form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn x963_representation(&self) -> Result<Vec<u8>> {
        self.0.x963_representation()
    }

    /// Validate and wrap a compressed public-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_compressed_representation(compressed: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(KeyAgreementPublicKey::from_compressed_representation(
            KeyAgreementAlgorithm::P384,
            compressed,
        )?))
    }

    /// Export this public key in compressed form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn compressed_representation(&self) -> Result<Vec<u8>> {
        self.0.compressed_representation()
    }

    /// Validate and wrap a DER public-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid for P384.
    pub fn from_der_representation(der: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self(KeyAgreementPublicKey::from_der_representation(
            KeyAgreementAlgorithm::P384,
            der,
        )?))
    }

    /// Export this public key in DER form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn der_representation(&self) -> Result<Vec<u8>> {
        self.0.der_representation()
    }

    /// Validate and wrap a PEM public-key representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is invalid for P384.
    pub fn from_pem_representation(pem: impl AsRef<str>) -> Result<Self> {
        Ok(Self(KeyAgreementPublicKey::from_pem_representation(
            KeyAgreementAlgorithm::P384,
            pem,
        )?))
    }

    /// Export this public key in PEM form.
    ///
    /// # Errors
    ///
    /// Returns an error if export fails.
    pub fn pem_representation(&self) -> Result<String> {
        self.0.pem_representation()
    }
}
