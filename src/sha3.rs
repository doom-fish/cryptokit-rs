//! SHA-3 hashing helpers.

use core::ffi::{c_char, c_void};
use core::fmt;
use std::ptr;
use std::ptr::NonNull;

use crate::error::{from_swift, CryptoKitError, Result};
use crate::ffi;
use crate::private::{bridge_bytes, bridge_status, hex};
use crate::sha::{Digest, HashFunction};

/// SHA-3 algorithms exposed by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Sha3Algorithm {
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl Sha3Algorithm {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::Sha3_256 => ffi::sha3_algorithm::SHA3_256,
            Self::Sha3_384 => ffi::sha3_algorithm::SHA3_384,
            Self::Sha3_512 => ffi::sha3_algorithm::SHA3_512,
        }
    }
}

macro_rules! sha3_digest_type {
    ($name:ident, $len:expr, $doc:literal) => {
        #[allow(non_camel_case_types)]
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Number of bytes in this digest type.
            pub const BYTE_COUNT: usize = $len;

            /// Build a typed digest from owned bytes.
            ///
            /// # Errors
            ///
            /// Returns an error if the byte length does not match the digest width.
            pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self> {
                let bytes = bytes.into();
                let actual = bytes.len();
                let array: [u8; $len] = bytes.as_slice().try_into().map_err(|_| {
                    CryptoKitError::InvalidArgument(format!(
                        "{} expects {} bytes, got {}",
                        stringify!($name),
                        $len,
                        actual
                    ))
                })?;
                Ok(Self(array))
            }

            /// Borrow the digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Consume the digest and return its bytes.
            #[must_use]
            pub fn into_bytes(self) -> Vec<u8> {
                self.0.to_vec()
            }
        }

        impl Digest for $name {
            const BYTE_COUNT: usize = Self::BYTE_COUNT;

            fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self> {
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

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex(self.as_bytes()))
            }
        }
    };
}

sha3_digest_type!(Sha3_256Digest, 32, "Typed SHA3-256 digest bytes.");
sha3_digest_type!(Sha3_384Digest, 48, "Typed SHA3-384 digest bytes.");
sha3_digest_type!(Sha3_512Digest, 64, "Typed SHA3-512 digest bytes.");

/// Hash input bytes with the selected SHA-3 algorithm.
///
/// # Errors
///
/// Returns an error if the Swift bridge rejects the request.
pub fn hash(algorithm: Sha3Algorithm, data: &[u8]) -> Result<Vec<u8>> {
    bridge_bytes(|out, out_len, error_out| unsafe {
        ffi::ck_sha3_hash(
            algorithm.as_ffi(),
            data.as_ptr(),
            data.len(),
            out,
            out_len,
            error_out,
        )
    })
}

#[derive(Debug)]
struct Sha3StateHandle {
    handle: Option<NonNull<c_void>>,
}

impl Sha3StateHandle {
    fn new(algorithm: Sha3Algorithm) -> Result<Self> {
        let mut error: *mut c_char = ptr::null_mut();
        let handle = unsafe { ffi::ck_sha3_hasher_create(algorithm.as_ffi(), &mut error) };
        let handle =
            NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::HASHING_FAILED, error))?;
        Ok(Self {
            handle: Some(handle),
        })
    }

    fn update(&self, data: &[u8]) -> Result<()> {
        let handle = self
            .handle
            .expect("SHA-3 state must not be used after finalize");
        bridge_status(|error_out| unsafe {
            ffi::ck_sha3_hasher_update(handle.as_ptr(), data.as_ptr(), data.len(), error_out)
        })
    }

    fn finalize(mut self) -> Result<Vec<u8>> {
        let handle = self
            .handle
            .take()
            .expect("SHA-3 state must not be finalized twice");
        let digest = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_sha3_hasher_finalize(handle.as_ptr(), out, out_len, error_out)
        })?;
        unsafe { ffi::ck_sha3_hasher_release(handle.as_ptr()) };
        Ok(digest)
    }
}

impl Drop for Sha3StateHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            unsafe { ffi::ck_sha3_hasher_release(handle.as_ptr()) };
        }
    }
}

macro_rules! sha3_hasher_type {
    ($name:ident, $digest:ident, $algorithm:expr, $fn_name:ident, $type_doc:literal, $fn_doc:literal) => {
        #[allow(non_camel_case_types)]
        #[doc = $type_doc]
        #[derive(Debug)]
        pub struct $name(Sha3StateHandle);

        impl HashFunction for $name {
            type Digest = $digest;

            fn new() -> Result<Self> {
                Ok(Self(Sha3StateHandle::new($algorithm)?))
            }

            fn update(&mut self, data: &[u8]) -> Result<()> {
                self.0.update(data)
            }

            fn finalize(self) -> Result<Self::Digest> {
                $digest::from_bytes(self.0.finalize()?)
            }
        }

        impl $name {
            /// Create a fresh SHA-3 hasher.
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
            $digest::from_bytes(hash($algorithm, data)?)
        }
    };
}

sha3_hasher_type!(
    Sha3_256,
    Sha3_256Digest,
    Sha3Algorithm::Sha3_256,
    sha3_256,
    "Streaming SHA3-256 state.",
    "Compute a SHA3-256 digest."
);
sha3_hasher_type!(
    Sha3_384,
    Sha3_384Digest,
    Sha3Algorithm::Sha3_384,
    sha3_384,
    "Streaming SHA3-384 state.",
    "Compute a SHA3-384 digest."
);
sha3_hasher_type!(
    Sha3_512,
    Sha3_512Digest,
    Sha3Algorithm::Sha3_512,
    sha3_512,
    "Streaming SHA3-512 state.",
    "Compute a SHA3-512 digest."
);
