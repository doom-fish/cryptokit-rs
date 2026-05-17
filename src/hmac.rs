//! Hash-based message authentication codes.

use core::any::type_name;
use core::ffi::{c_char, c_void};
use core::fmt;
use core::marker::PhantomData;
use std::ptr;
use std::ptr::NonNull;

use crate::error::{from_swift, Result};
use crate::ffi;
use crate::private::{bridge_bytes, bridge_flag, bridge_status, hex, validate_byte_count};
use crate::sha::{HashFunction, Sha384, Sha256, Sha512};
use crate::symmetric::SymmetricKey;

/// Typed message-authentication-code values produced by `CryptoKit`.
pub trait MessageAuthenticationCode: AsRef<[u8]> + Clone + Eq + core::hash::Hash + fmt::Display {
    /// Number of bytes in this MAC.
    fn byte_count(&self) -> usize;

    /// Borrow the MAC bytes.
    fn as_bytes(&self) -> &[u8];

    /// Consume the MAC and return its bytes.
    fn into_bytes(self) -> Vec<u8>;
}

/// HMAC algorithms exposed by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HmacAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HmacAlgorithm {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::Sha256 => ffi::hmac_algorithm::SHA256,
            Self::Sha384 => ffi::hmac_algorithm::SHA384,
            Self::Sha512 => ffi::hmac_algorithm::SHA512,
        }
    }
}

/// Hash functions that can back `CryptoKit` HMAC values.
pub trait HmacHashFunction: HashFunction {
    /// Dynamic algorithm selector used by the FFI bridge.
    const HMAC_ALGORITHM: HmacAlgorithm;
}

impl HmacHashFunction for Sha256 {
    const HMAC_ALGORITHM: HmacAlgorithm = HmacAlgorithm::Sha256;
}

impl HmacHashFunction for Sha384 {
    const HMAC_ALGORITHM: HmacAlgorithm = HmacAlgorithm::Sha384;
}

impl HmacHashFunction for Sha512 {
    const HMAC_ALGORITHM: HmacAlgorithm = HmacAlgorithm::Sha512;
}

/// Typed `CryptoKit.HashedAuthenticationCode<H>` bytes.
#[derive(Debug)]
pub struct HashedAuthenticationCode<H: HashFunction> {
    bytes: Vec<u8>,
    _marker: PhantomData<H>,
}

impl<H: HashFunction> Clone for HashedAuthenticationCode<H> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _marker: PhantomData,
        }
    }
}

impl<H: HashFunction> PartialEq for HashedAuthenticationCode<H> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<H: HashFunction> Eq for HashedAuthenticationCode<H> {}

impl<H: HashFunction> core::hash::Hash for HashedAuthenticationCode<H> {
    fn hash<T: core::hash::Hasher>(&self, state: &mut T) {
        core::hash::Hash::hash(&self.bytes, state);
    }
}

impl<H: HashFunction> HashedAuthenticationCode<H> {
    /// Build a typed MAC from owned bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte length does not match the hash output width.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let type_name = format!("HashedAuthenticationCode<{}>", type_name::<H>());
        let bytes = validate_byte_count(
            &type_name,
            <H::Digest as crate::sha::Digest>::BYTE_COUNT,
            bytes.into(),
        )?;
        Ok(Self {
            bytes,
            _marker: PhantomData,
        })
    }

    /// Borrow the MAC bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the MAC and return its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of bytes in this MAC.
    #[must_use]
    pub fn byte_count(&self) -> usize {
        self.bytes.len()
    }
}

impl<H: HashFunction> MessageAuthenticationCode for HashedAuthenticationCode<H> {
    fn byte_count(&self) -> usize {
        Self::byte_count(self)
    }

    fn as_bytes(&self) -> &[u8] {
        Self::as_bytes(self)
    }

    fn into_bytes(self) -> Vec<u8> {
        Self::into_bytes(self)
    }
}

impl<H: HashFunction> AsRef<[u8]> for HashedAuthenticationCode<H> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<H: HashFunction> fmt::Display for HashedAuthenticationCode<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(self.as_bytes()))
    }
}

#[derive(Debug)]
struct HmacStateHandle {
    handle: Option<NonNull<c_void>>,
}

impl HmacStateHandle {
    fn new(algorithm: HmacAlgorithm, key: &SymmetricKey) -> Result<Self> {
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe {
            ffi::ck_hmac_hasher_create(
                algorithm.as_ffi(),
                key.as_bytes().as_ptr(),
                key.as_bytes().len(),
                &mut error,
            )
        };
        let handle = NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::HMAC_FAILED, error))?;
        Ok(Self {
            handle: Some(handle),
        })
    }

    fn update(&self, data: &[u8]) -> Result<()> {
        let handle = self
            .handle
            .expect("HMAC state must not be used after finalize");
        bridge_status(|error_out| unsafe {
            ffi::ck_hmac_hasher_update(handle.as_ptr(), data.as_ptr(), data.len(), error_out)
        })
    }

    fn finalize(mut self) -> Result<Vec<u8>> {
        let handle = self
            .handle
            .take()
            .expect("HMAC state must not be finalized twice");
        let code = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_hmac_hasher_finalize(handle.as_ptr(), out, out_len, error_out)
        })?;
        unsafe { ffi::ck_hmac_hasher_release(handle.as_ptr()) };
        Ok(code)
    }
}

impl Drop for HmacStateHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            unsafe { ffi::ck_hmac_hasher_release(handle.as_ptr()) };
        }
    }
}

/// Streaming HMAC state backed by `CryptoKit.HMAC<H>`.
#[derive(Debug)]
pub struct Hmac<H: HmacHashFunction> {
    handle: HmacStateHandle,
    _marker: PhantomData<H>,
}

impl<H: HmacHashFunction> Hmac<H> {
    /// Create a fresh HMAC state for the supplied symmetric key.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn new(key: &SymmetricKey) -> Result<Self> {
        Ok(Self {
            handle: HmacStateHandle::new(H::HMAC_ALGORITHM, key)?,
            _marker: PhantomData,
        })
    }

    /// Feed more bytes into the MAC state.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        self.handle.update(data)
    }

    /// Finalize the MAC state and return a typed authentication code.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn finalize(self) -> Result<HashedAuthenticationCode<H>> {
        HashedAuthenticationCode::from_bytes(self.handle.finalize()?)
    }

    /// Compute a typed authentication code for a complete message.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn authentication_code(
        message: &[u8],
        key: &SymmetricKey,
    ) -> Result<HashedAuthenticationCode<H>> {
        hmac_typed::<H>(key, message)
    }

    /// Verify an authentication code for a complete message.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn is_valid_authentication_code<C>(
        authentication_code: C,
        message: &[u8],
        key: &SymmetricKey,
    ) -> Result<bool>
    where
        C: AsRef<[u8]>,
    {
        is_valid_authentication_code::<H, C>(authentication_code, message, key)
    }
}

/// Compute an HMAC for the given message and symmetric key.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hmac(algorithm: HmacAlgorithm, key: &SymmetricKey, message: &[u8]) -> Result<Vec<u8>> {
    bridge_bytes(|out, out_len, error_out| unsafe {
        ffi::ck_hmac(
            algorithm.as_ffi(),
            key.as_bytes().as_ptr(),
            key.as_bytes().len(),
            message.as_ptr(),
            message.len(),
            out,
            out_len,
            error_out,
        )
    })
}

/// Compute a typed HMAC for the given message and symmetric key.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hmac_typed<H>(key: &SymmetricKey, message: &[u8]) -> Result<HashedAuthenticationCode<H>>
where
    H: HmacHashFunction,
{
    HashedAuthenticationCode::from_bytes(hmac(H::HMAC_ALGORITHM, key, message)?)
}

/// Verify an HMAC for the given message and symmetric key.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn is_valid_authentication_code<H, C>(
    authentication_code: C,
    message: &[u8],
    key: &SymmetricKey,
) -> Result<bool>
where
    H: HmacHashFunction,
    C: AsRef<[u8]>,
{
    let authentication_code = authentication_code.as_ref();
    bridge_flag(|out_valid, error_out| unsafe {
        ffi::ck_hmac_verify(
            H::HMAC_ALGORITHM.as_ffi(),
            key.as_bytes().as_ptr(),
            key.as_bytes().len(),
            message.as_ptr(),
            message.len(),
            authentication_code.as_ptr(),
            authentication_code.len(),
            out_valid,
            error_out,
        )
    })
}

/// Compute an HMAC-SHA256 authentication code.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hmac_sha256(message: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
    hmac(HmacAlgorithm::Sha256, key, message)
}

/// Compute a typed HMAC-SHA256 authentication code.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hmac_sha256_code(
    message: &[u8],
    key: &SymmetricKey,
) -> Result<HashedAuthenticationCode<Sha256>> {
    hmac_typed::<Sha256>(key, message)
}

/// Verify an HMAC-SHA256 authentication code.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn is_valid_hmac_sha256<C>(
    authentication_code: C,
    message: &[u8],
    key: &SymmetricKey,
) -> Result<bool>
where
    C: AsRef<[u8]>,
{
    is_valid_authentication_code::<Sha256, C>(authentication_code, message, key)
}

/// Compute an HMAC-SHA384 authentication code.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hmac_sha384(message: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
    hmac(HmacAlgorithm::Sha384, key, message)
}

/// Compute a typed HMAC-SHA384 authentication code.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hmac_sha384_code(
    message: &[u8],
    key: &SymmetricKey,
) -> Result<HashedAuthenticationCode<Sha384>> {
    hmac_typed::<Sha384>(key, message)
}

/// Verify an HMAC-SHA384 authentication code.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn is_valid_hmac_sha384<C>(
    authentication_code: C,
    message: &[u8],
    key: &SymmetricKey,
) -> Result<bool>
where
    C: AsRef<[u8]>,
{
    is_valid_authentication_code::<Sha384, C>(authentication_code, message, key)
}

/// Compute an HMAC-SHA512 authentication code.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hmac_sha512(message: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
    hmac(HmacAlgorithm::Sha512, key, message)
}

/// Compute a typed HMAC-SHA512 authentication code.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn hmac_sha512_code(
    message: &[u8],
    key: &SymmetricKey,
) -> Result<HashedAuthenticationCode<Sha512>> {
    hmac_typed::<Sha512>(key, message)
}

/// Verify an HMAC-SHA512 authentication code.
///
/// # Errors
///
/// Returns an error if the `CryptoKit` bridge rejects the request.
pub fn is_valid_hmac_sha512<C>(
    authentication_code: C,
    message: &[u8],
    key: &SymmetricKey,
) -> Result<bool>
where
    C: AsRef<[u8]>,
{
    is_valid_authentication_code::<Sha512, C>(authentication_code, message, key)
}

/// Convenience alias for streaming HMAC-SHA256 state.
pub type HmacSha256 = Hmac<Sha256>;

/// Convenience alias for streaming HMAC-SHA384 state.
pub type HmacSha384 = Hmac<Sha384>;

/// Convenience alias for streaming HMAC-SHA512 state.
pub type HmacSha512 = Hmac<Sha512>;
