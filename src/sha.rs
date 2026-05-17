//! SHA-family hashing helpers.

use core::ffi::{c_char, c_void};
use core::fmt;
use std::ptr;
use std::ptr::NonNull;

use crate::error::{from_swift, Result};
use crate::ffi;
use crate::private::{bridge_bytes, bridge_status};

/// Typed digest values produced by `CryptoKit` hash functions.
pub trait Digest: AsRef<[u8]> + Clone + Eq + core::hash::Hash + fmt::Display {
    /// Exact number of bytes in the digest.
    const BYTE_COUNT: usize;

    /// Validate and wrap owned digest bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte length does not match the digest width.
    fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self>
    where
        Self: Sized;

    /// Borrow the digest bytes.
    fn as_bytes(&self) -> &[u8];

    /// Consume the digest and return its bytes.
    fn into_bytes(self) -> Vec<u8>;
}

/// Streaming hash functions exposed by `CryptoKit`.
pub trait HashFunction: Sized {
    /// Typed digest returned by this hash function.
    type Digest: Digest;

    /// Create a new hasher.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    fn new() -> Result<Self>;

    /// Feed more bytes into the hash state.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    fn update(&mut self, data: &[u8]) -> Result<()>;

    /// Finalize the hash state and return a typed digest.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    fn finalize(self) -> Result<Self::Digest>;
}

/// SHA-2 hash functions exposed by this crate.
pub trait Sha2HashFunction: HashFunction {
    /// Dynamic algorithm selector used by the FFI bridge.
    const ALGORITHM: ShaAlgorithm;
}

/// SHA-family algorithms exposed by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ShaAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl ShaAlgorithm {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::Sha256 => ffi::hash_algorithm::SHA256,
            Self::Sha384 => ffi::hash_algorithm::SHA384,
            Self::Sha512 => ffi::hash_algorithm::SHA512,
        }
    }
}

macro_rules! digest_type {
    ($name:ident, $len:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Number of bytes in this digest type.
            pub const BYTE_COUNT: usize = $len;

            /// Build a typed digest from owned bytes.
            ///
            /// # Errors
            ///
            /// Returns an error if the byte length does not match the digest width.
            pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> crate::error::Result<Self> {
                let bytes = crate::private::validate_byte_count(
                    stringify!($name),
                    Self::BYTE_COUNT,
                    bytes.into(),
                )?;
                Ok(Self(bytes))
            }

            /// Borrow the digest bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Consume the digest and return its bytes.
            #[must_use]
            pub fn into_bytes(self) -> Vec<u8> {
                self.0
            }
        }

        impl crate::sha::Digest for $name {
            const BYTE_COUNT: usize = Self::BYTE_COUNT;

            fn from_bytes(bytes: impl Into<Vec<u8>>) -> crate::error::Result<Self> {
                Self::from_bytes(bytes)
            }

            fn as_bytes(&self) -> &[u8] {
                Self::as_bytes(self)
            }

            fn into_bytes(self) -> Vec<u8> {
                Self::into_bytes(self)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&crate::private::hex(self.as_bytes()))
            }
        }
    };
}

pub(crate) use digest_type;

digest_type!(Sha256Digest, 32, "Typed SHA-256 digest bytes.");
digest_type!(Sha384Digest, 48, "Typed SHA-384 digest bytes.");
digest_type!(Sha512Digest, 64, "Typed SHA-512 digest bytes.");

/// Hash input bytes with a SHA-family algorithm.
///
/// # Errors
///
/// Returns an error if the Swift bridge rejects the request.
pub fn digest(algorithm: ShaAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    bridge_bytes(|out, out_len, error_out| unsafe {
        match algorithm {
            ShaAlgorithm::Sha256 => {
                ffi::ck_sha256(data.as_ptr(), data.len(), out, out_len, error_out)
            }
            ShaAlgorithm::Sha384 => {
                ffi::ck_sha384(data.as_ptr(), data.len(), out, out_len, error_out)
            }
            ShaAlgorithm::Sha512 => {
                ffi::ck_sha512(data.as_ptr(), data.len(), out, out_len, error_out)
            }
        }
    })
}

/// Hash input bytes with a SHA-family algorithm and return a typed digest.
///
/// # Errors
///
/// Returns an error if the Swift bridge rejects the request.
pub fn digest_typed<H>(data: &[u8]) -> Result<H::Digest>
where
    H: Sha2HashFunction,
{
    H::Digest::from_bytes(digest(H::ALGORITHM, data)?)
}

#[derive(Debug)]
pub(crate) struct HashStateHandle {
    handle: Option<NonNull<c_void>>,
}

impl HashStateHandle {
    pub(crate) fn new(algorithm: i32) -> Result<Self> {
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe { ffi::ck_hash_hasher_create(algorithm, &mut error) };
        let handle = NonNull::new(handle)
            .ok_or_else(|| from_swift(ffi::status::HASHING_FAILED, error))?;
        Ok(Self {
            handle: Some(handle),
        })
    }

    pub(crate) fn update(&self, data: &[u8]) -> Result<()> {
        let handle = self
            .handle
            .expect("hash state must not be used after finalize");
        bridge_status(|error_out| unsafe {
            ffi::ck_hash_hasher_update(handle.as_ptr(), data.as_ptr(), data.len(), error_out)
        })
    }

    pub(crate) fn finalize(mut self) -> Result<Vec<u8>> {
        let handle = self
            .handle
            .take()
            .expect("hash state must not be finalized twice");
        let digest = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_hash_hasher_finalize(handle.as_ptr(), out, out_len, error_out)
        })?;
        unsafe { ffi::ck_hash_hasher_release(handle.as_ptr()) };
        Ok(digest)
    }
}

impl Drop for HashStateHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            unsafe { ffi::ck_hash_hasher_release(handle.as_ptr()) };
        }
    }
}

macro_rules! sha_hasher_type {
    ($name:ident, $digest:ident, $algorithm:expr, $fn_name:ident, $type_doc:literal, $fn_doc:literal) => {
        #[doc = $type_doc]
        #[derive(Debug)]
        pub struct $name(HashStateHandle);

        impl HashFunction for $name {
            type Digest = $digest;

            fn new() -> Result<Self> {
                Ok(Self(HashStateHandle::new($algorithm.as_ffi())?))
            }

            fn update(&mut self, data: &[u8]) -> Result<()> {
                self.0.update(data)
            }

            fn finalize(self) -> Result<Self::Digest> {
                $digest::from_bytes(self.0.finalize()?)
            }
        }

        impl Sha2HashFunction for $name {
            const ALGORITHM: ShaAlgorithm = $algorithm;
        }

        impl $name {
            /// Create a fresh hasher.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn new() -> Result<Self> {
                <Self as HashFunction>::new()
            }

            /// Feed more bytes into the hash state.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn update(&mut self, data: &[u8]) -> Result<()> {
                <Self as HashFunction>::update(self, data)
            }

            /// Finalize the hash state and return a typed digest.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn finalize(self) -> Result<$digest> {
                <Self as HashFunction>::finalize(self)
            }
        }

        #[doc = $fn_doc]
        ///
        /// # Errors
        ///
        /// Returns an error if the Swift bridge rejects the request.
        pub fn $fn_name(data: &[u8]) -> Result<$digest> {
            digest_typed::<$name>(data)
        }
    };
}

sha_hasher_type!(
    Sha256,
    Sha256Digest,
    ShaAlgorithm::Sha256,
    sha256_digest,
    "Streaming SHA-256 state.",
    "Compute a typed SHA-256 digest."
);
sha_hasher_type!(
    Sha384,
    Sha384Digest,
    ShaAlgorithm::Sha384,
    sha384_digest,
    "Streaming SHA-384 state.",
    "Compute a typed SHA-384 digest."
);
sha_hasher_type!(
    Sha512,
    Sha512Digest,
    ShaAlgorithm::Sha512,
    sha512_digest,
    "Streaming SHA-512 state.",
    "Compute a typed SHA-512 digest."
);

/// Compute a SHA-256 digest.
///
/// # Errors
///
/// Returns an error if hashing fails.
pub fn sha256(data: &[u8]) -> Result<Vec<u8>> {
    digest(ShaAlgorithm::Sha256, data)
}

/// Compute a SHA-384 digest.
///
/// # Errors
///
/// Returns an error if hashing fails.
pub fn sha384(data: &[u8]) -> Result<Vec<u8>> {
    digest(ShaAlgorithm::Sha384, data)
}

/// Compute a SHA-512 digest.
///
/// # Errors
///
/// Returns an error if hashing fails.
pub fn sha512(data: &[u8]) -> Result<Vec<u8>> {
    digest(ShaAlgorithm::Sha512, data)
}

#[allow(non_camel_case_types)]
/// Compatibility alias matching the macOS 26 `CryptoKit` typealias.
pub type SHA2_256 = Sha256;

#[allow(non_camel_case_types)]
/// Compatibility alias matching the macOS 26 `CryptoKit` typealias.
pub type SHA2_384 = Sha384;

#[allow(non_camel_case_types)]
/// Compatibility alias matching the macOS 26 `CryptoKit` typealias.
pub type SHA2_512 = Sha512;
