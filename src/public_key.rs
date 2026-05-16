//! Signing and key-agreement keys backed by raw `CryptoKit` representations.

use crate::error::Result;
use crate::ffi;
use crate::hkdf::hkdf_sha256;
use crate::private::{bridge_bytes, bridge_flag, ensure_same_algorithm};
use crate::symmetric::SymmetricKey;

/// Supported signing algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigningAlgorithm {
    P256,
    P384,
    P521,
    Ed25519,
}

impl SigningAlgorithm {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::P256 => ffi::signing_algorithm::P256,
            Self::P384 => ffi::signing_algorithm::P384,
            Self::P521 => ffi::signing_algorithm::P521,
            Self::Ed25519 => ffi::signing_algorithm::ED25519,
        }
    }
}

/// Raw private signing key bytes plus algorithm metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPrivateKey {
    algorithm: SigningAlgorithm,
    raw: Vec<u8>,
}

impl SigningPrivateKey {
    /// Generate a new private signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if the `CryptoKit` bridge rejects the request.
    pub fn generate(algorithm: SigningAlgorithm) -> Result<Self> {
        let raw = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_signing_private_key_generate(algorithm.as_ffi(), out, out_len, error_out)
        })?;
        Ok(Self { algorithm, raw })
    }

    /// Validate and wrap raw private-key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid `CryptoKit` private-key representation.
    pub fn from_raw_representation(
        algorithm: SigningAlgorithm,
        raw: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let raw = raw.into();
        let canonical = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_signing_private_key_validate(
                algorithm.as_ffi(),
                raw.as_ptr(),
                raw.len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(Self {
            algorithm,
            raw: canonical,
        })
    }

    /// Algorithm carried by this key.
    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// Borrow the raw private-key bytes.
    #[must_use]
    pub fn raw_representation(&self) -> &[u8] {
        &self.raw
    }

    /// Consume the key and return its raw representation.
    #[must_use]
    pub fn into_raw_representation(self) -> Vec<u8> {
        self.raw
    }

    /// Derive the corresponding public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the `CryptoKit` bridge rejects the request.
    pub fn public_key(&self) -> Result<SigningPublicKey> {
        let raw = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_signing_public_key_from_private(
                self.algorithm.as_ffi(),
                self.raw.as_ptr(),
                self.raw.len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(SigningPublicKey {
            algorithm: self.algorithm,
            raw,
        })
    }

    /// Sign a message with this private key.
    ///
    /// For P-256 / P-384 / P-521, signatures are returned in `CryptoKit`'s fixed-width raw form.
    /// Ed25519 signatures are returned as 64-byte raw signatures.
    ///
    /// # Errors
    ///
    /// Returns an error if the `CryptoKit` bridge rejects the request.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_sign(
                self.algorithm.as_ffi(),
                self.raw.as_ptr(),
                self.raw.len(),
                message.as_ptr(),
                message.len(),
                out,
                out_len,
                error_out,
            )
        })
    }
}

/// Raw public signing key bytes plus algorithm metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPublicKey {
    algorithm: SigningAlgorithm,
    raw: Vec<u8>,
}

impl SigningPublicKey {
    /// Validate and wrap raw public-key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid `CryptoKit` public-key representation.
    pub fn from_raw_representation(
        algorithm: SigningAlgorithm,
        raw: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let raw = raw.into();
        let canonical = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_signing_public_key_validate(
                algorithm.as_ffi(),
                raw.as_ptr(),
                raw.len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(Self {
            algorithm,
            raw: canonical,
        })
    }

    /// Algorithm carried by this key.
    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// Borrow the raw public-key bytes.
    #[must_use]
    pub fn raw_representation(&self) -> &[u8] {
        &self.raw
    }

    /// Consume the key and return its raw representation.
    #[must_use]
    pub fn into_raw_representation(self) -> Vec<u8> {
        self.raw
    }

    /// Verify a signature for a message.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or signature encoding is invalid for the selected algorithm.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        bridge_flag(|out_valid, error_out| unsafe {
            ffi::ck_verify(
                self.algorithm.as_ffi(),
                self.raw.as_ptr(),
                self.raw.len(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
                out_valid,
                error_out,
            )
        })
    }
}

/// Supported key-agreement algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyAgreementAlgorithm {
    P256,
    P384,
    P521,
    X25519,
}

impl KeyAgreementAlgorithm {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::P256 => ffi::key_agreement_algorithm::P256,
            Self::P384 => ffi::key_agreement_algorithm::P384,
            Self::P521 => ffi::key_agreement_algorithm::P521,
            Self::X25519 => ffi::key_agreement_algorithm::X25519,
        }
    }
}

/// Raw private key-agreement bytes plus algorithm metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAgreementPrivateKey {
    algorithm: KeyAgreementAlgorithm,
    raw: Vec<u8>,
}

impl KeyAgreementPrivateKey {
    /// Generate a new private key-agreement key.
    ///
    /// # Errors
    ///
    /// Returns an error if the `CryptoKit` bridge rejects the request.
    pub fn generate(algorithm: KeyAgreementAlgorithm) -> Result<Self> {
        let raw = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_key_agreement_private_key_generate(algorithm.as_ffi(), out, out_len, error_out)
        })?;
        Ok(Self { algorithm, raw })
    }

    /// Validate and wrap raw private-key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid `CryptoKit` private-key representation.
    pub fn from_raw_representation(
        algorithm: KeyAgreementAlgorithm,
        raw: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let raw = raw.into();
        let canonical = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_key_agreement_private_key_validate(
                algorithm.as_ffi(),
                raw.as_ptr(),
                raw.len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(Self {
            algorithm,
            raw: canonical,
        })
    }

    /// Algorithm carried by this key.
    #[must_use]
    pub const fn algorithm(&self) -> KeyAgreementAlgorithm {
        self.algorithm
    }

    /// Borrow the raw private-key bytes.
    #[must_use]
    pub fn raw_representation(&self) -> &[u8] {
        &self.raw
    }

    /// Consume the key and return its raw representation.
    #[must_use]
    pub fn into_raw_representation(self) -> Vec<u8> {
        self.raw
    }

    /// Derive the corresponding public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the `CryptoKit` bridge rejects the request.
    pub fn public_key(&self) -> Result<KeyAgreementPublicKey> {
        let raw = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_key_agreement_public_key_from_private(
                self.algorithm.as_ffi(),
                self.raw.as_ptr(),
                self.raw.len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(KeyAgreementPublicKey {
            algorithm: self.algorithm,
            raw,
        })
    }

    /// Perform ECDH / X25519 key agreement with a peer public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the algorithms do not match or the `CryptoKit` bridge rejects the request.
    pub fn shared_secret(&self, peer: &KeyAgreementPublicKey) -> Result<SharedSecret> {
        ensure_same_algorithm(self.algorithm, peer.algorithm, "key agreement")?;
        let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_key_agreement_shared_secret(
                self.algorithm.as_ffi(),
                self.raw.as_ptr(),
                self.raw.len(),
                peer.raw.as_ptr(),
                peer.raw.len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(SharedSecret { bytes })
    }
}

/// Raw public key-agreement bytes plus algorithm metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAgreementPublicKey {
    algorithm: KeyAgreementAlgorithm,
    raw: Vec<u8>,
}

impl KeyAgreementPublicKey {
    /// Validate and wrap raw public-key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid `CryptoKit` public-key representation.
    pub fn from_raw_representation(
        algorithm: KeyAgreementAlgorithm,
        raw: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let raw = raw.into();
        let canonical = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_key_agreement_public_key_validate(
                algorithm.as_ffi(),
                raw.as_ptr(),
                raw.len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(Self {
            algorithm,
            raw: canonical,
        })
    }

    /// Algorithm carried by this key.
    #[must_use]
    pub const fn algorithm(&self) -> KeyAgreementAlgorithm {
        self.algorithm
    }

    /// Borrow the raw public-key bytes.
    #[must_use]
    pub fn raw_representation(&self) -> &[u8] {
        &self.raw
    }

    /// Consume the key and return its raw representation.
    #[must_use]
    pub fn into_raw_representation(self) -> Vec<u8> {
        self.raw
    }
}

/// Shared secret bytes returned by a key-agreement operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedSecret {
    bytes: Vec<u8>,
}

impl SharedSecret {
    /// Borrow the raw shared-secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the shared secret and return its raw bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Derive a symmetric key from this shared secret with HKDF-SHA256.
    ///
    /// # Errors
    ///
    /// Returns an error if the `CryptoKit` bridge rejects the request.
    pub fn hkdf_sha256(&self, salt: &[u8], info: &[u8], output_len: usize) -> Result<SymmetricKey> {
        let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_shared_secret_hkdf_sha256(
                self.bytes.as_ptr(),
                self.bytes.len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                output_len,
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(SymmetricKey::from_bytes(bytes))
    }

    /// Treat this shared secret as generic input key material for HKDF-SHA256.
    ///
    /// # Errors
    ///
    /// Returns an error if the `CryptoKit` bridge rejects the request.
    pub fn hkdf_via_input_key_material(
        &self,
        salt: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<SymmetricKey> {
        hkdf_sha256(
            &SymmetricKey::from_bytes(self.bytes.clone()),
            salt,
            info,
            output_len,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        KeyAgreementAlgorithm, KeyAgreementPrivateKey, Result, SigningAlgorithm, SigningPrivateKey,
    };

    #[test]
    fn ed25519_signatures_round_trip() -> Result<()> {
        let private_key = SigningPrivateKey::generate(SigningAlgorithm::Ed25519)?;
        let public_key = private_key.public_key()?;
        let message = b"cryptokit test message";
        let signature = private_key.sign(message)?;

        assert!(public_key.verify(message, &signature)?);
        Ok(())
    }

    #[test]
    fn p256_shared_secrets_match_for_both_peers() -> Result<()> {
        let alice = KeyAgreementPrivateKey::generate(KeyAgreementAlgorithm::P256)?;
        let bob = KeyAgreementPrivateKey::generate(KeyAgreementAlgorithm::P256)?;

        let alice_secret = alice.shared_secret(&bob.public_key()?)?;
        let bob_secret = bob.shared_secret(&alice.public_key()?)?;
        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());

        let derived = alice_secret.hkdf_sha256(b"salt", b"info", 32)?;
        assert_eq!(derived.as_bytes().len(), 32);
        Ok(())
    }
}
