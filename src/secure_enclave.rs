//! Secure Enclave-backed P-256 keys.

use core::ffi::{c_char, c_void};
use std::ptr;
use std::ptr::NonNull;

use crate::error::{from_swift, Result};
use crate::ffi;
use crate::p256::{P256KeyAgreementPublicKey, P256SigningPublicKey};
use crate::private::{bridge_bytes, bridge_flag};
use crate::public_key::SharedSecret;

/// Query whether the current machine reports Secure Enclave availability.
///
/// # Errors
///
/// Returns an error if the Swift bridge rejects the query.
pub fn is_available() -> Result<bool> {
    bridge_flag(|out_available, error_out| unsafe {
        ffi::ck_secure_enclave_is_available(out_available, error_out)
    })
}

/// A Secure Enclave-backed P-256 signing private key.
#[derive(Debug)]
pub struct SecureEnclaveSigningPrivateKey {
    handle: NonNull<c_void>,
}

impl SecureEnclaveSigningPrivateKey {
    /// Generate a new Secure Enclave signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or key creation fails.
    pub fn generate() -> Result<Self> {
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe { ffi::ck_secure_enclave_signing_private_key_generate(&mut error) };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Export the matching software-verifiable P-256 public key.
    ///
    /// # Errors
    ///
    /// Returns an error if public-key export fails.
    pub fn public_key(&self) -> Result<P256SigningPublicKey> {
        let raw = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_signing_private_key_public_key(
                self.handle.as_ptr(),
                out,
                out_len,
                error_out,
            )
        })?;
        P256SigningPublicKey::from_raw_representation(raw)
    }

    /// Sign a message with the Secure Enclave key.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_signing_private_key_sign(
                self.handle.as_ptr(),
                message.as_ptr(),
                message.len(),
                out,
                out_len,
                error_out,
            )
        })
    }
}

impl Drop for SecureEnclaveSigningPrivateKey {
    fn drop(&mut self) {
        unsafe { ffi::ck_secure_enclave_signing_private_key_release(self.handle.as_ptr()) };
    }
}

/// A Secure Enclave-backed P-256 key-agreement private key.
#[derive(Debug)]
pub struct SecureEnclaveKeyAgreementPrivateKey {
    handle: NonNull<c_void>,
}

impl SecureEnclaveKeyAgreementPrivateKey {
    /// Generate a new Secure Enclave key-agreement key.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or key creation fails.
    pub fn generate() -> Result<Self> {
        let mut error: *mut c_char = ptr::null_mut();
        let handle =
            unsafe { ffi::ck_secure_enclave_key_agreement_private_key_generate(&mut error) };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))?;
        Ok(Self { handle })
    }

    /// Export the matching software-verifiable P-256 public key.
    ///
    /// # Errors
    ///
    /// Returns an error if public-key export fails.
    pub fn public_key(&self) -> Result<P256KeyAgreementPublicKey> {
        let raw = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_key_agreement_private_key_public_key(
                self.handle.as_ptr(),
                out,
                out_len,
                error_out,
            )
        })?;
        P256KeyAgreementPublicKey::from_raw_representation(raw)
    }

    /// Derive a shared secret with a software P-256 public key.
    ///
    /// # Errors
    ///
    /// Returns an error if key agreement fails.
    pub fn shared_secret(&self, peer: &P256KeyAgreementPublicKey) -> Result<SharedSecret> {
        let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_key_agreement_private_key_shared_secret(
                self.handle.as_ptr(),
                peer.raw_representation().as_ptr(),
                peer.raw_representation().len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(SharedSecret::from_bytes(bytes))
    }
}

impl Drop for SecureEnclaveKeyAgreementPrivateKey {
    fn drop(&mut self) {
        unsafe { ffi::ck_secure_enclave_key_agreement_private_key_release(self.handle.as_ptr()) };
    }
}
