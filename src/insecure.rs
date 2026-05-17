//! Legacy compatibility hashes from `CryptoKit.Insecure`.

use crate::error::Result;
use crate::ffi;
use crate::private::bridge_bytes;
use crate::sha::{digest_type, Digest, HashFunction, HashStateHandle};

/// Legacy hash algorithms exposed by `CryptoKit.Insecure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InsecureHashAlgorithm {
    Md5,
    Sha1,
}

impl InsecureHashAlgorithm {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::Md5 => ffi::hash_algorithm::MD5,
            Self::Sha1 => ffi::hash_algorithm::SHA1,
        }
    }
}

/// Streaming legacy hash functions exposed by `CryptoKit.Insecure`.
pub trait InsecureHashFunction: HashFunction {
    /// Dynamic algorithm selector used by the FFI bridge.
    const ALGORITHM: InsecureHashAlgorithm;
}

digest_type!(Md5Digest, 16, "Typed MD5 digest bytes.");
digest_type!(Sha1Digest, 20, "Typed SHA-1 digest bytes.");

/// Hash input bytes with a legacy compatibility algorithm.
///
/// # Errors
///
/// Returns an error if the Swift bridge rejects the request.
pub fn hash(algorithm: InsecureHashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    bridge_bytes(|out, out_len, error_out| unsafe {
        match algorithm {
            InsecureHashAlgorithm::Md5 => {
                ffi::ck_md5(data.as_ptr(), data.len(), out, out_len, error_out)
            }
            InsecureHashAlgorithm::Sha1 => {
                ffi::ck_sha1(data.as_ptr(), data.len(), out, out_len, error_out)
            }
        }
    })
}

/// Hash input bytes with a legacy compatibility algorithm and return a typed digest.
///
/// # Errors
///
/// Returns an error if the Swift bridge rejects the request.
pub fn hash_typed<H>(data: &[u8]) -> Result<H::Digest>
where
    H: InsecureHashFunction,
{
    H::Digest::from_bytes(hash(H::ALGORITHM, data)?)
}

macro_rules! insecure_hasher_type {
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

        impl InsecureHashFunction for $name {
            const ALGORITHM: InsecureHashAlgorithm = $algorithm;
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
            hash_typed::<$name>(data)
        }
    };
}

insecure_hasher_type!(
    Md5,
    Md5Digest,
    InsecureHashAlgorithm::Md5,
    md5_digest,
    "Streaming MD5 state.",
    "Compute a typed MD5 digest."
);
insecure_hasher_type!(
    Sha1,
    Sha1Digest,
    InsecureHashAlgorithm::Sha1,
    sha1_digest,
    "Streaming SHA-1 state.",
    "Compute a typed SHA-1 digest."
);

/// Compute an MD5 digest.
///
/// # Errors
///
/// Returns an error if hashing fails.
pub fn md5(data: &[u8]) -> Result<Vec<u8>> {
    hash(InsecureHashAlgorithm::Md5, data)
}

/// Compute a SHA-1 digest.
///
/// # Errors
///
/// Returns an error if hashing fails.
pub fn sha1(data: &[u8]) -> Result<Vec<u8>> {
    hash(InsecureHashAlgorithm::Sha1, data)
}
