//! Errors produced by the `CryptoKit` bridge.

use core::ffi::c_char;
use core::fmt;

use libc::free;

use crate::ffi;

/// Convenient result alias used throughout this crate.
pub type Result<T, E = CryptoKitError> = std::result::Result<T, E>;

/// Top-level error type returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoKitError {
    /// Invalid input crossed the FFI boundary.
    InvalidArgument(String),
    /// Authenticated encryption failed.
    EncryptionFailed(String),
    /// Authenticated decryption failed.
    DecryptionFailed(String),
    /// Hashing failed.
    HashingFailed(String),
    /// HMAC failed.
    HmacFailed(String),
    /// HKDF derivation failed.
    HkdfFailed(String),
    /// Key creation, validation, or export failed.
    KeyOperationFailed(String),
    /// Signing failed.
    SignatureFailed(String),
    /// Key agreement failed.
    AgreementFailed(String),
    /// Catch-all for unmapped Swift-side errors.
    Unknown { code: i32, message: String },
}

impl CryptoKitError {
    /// Numeric status code reported by the Swift bridge.
    #[must_use]
    pub const fn code(&self) -> i32 {
        match self {
            Self::InvalidArgument(_) => ffi::status::INVALID_ARGUMENT,
            Self::EncryptionFailed(_) => ffi::status::ENCRYPTION_FAILED,
            Self::DecryptionFailed(_) => ffi::status::DECRYPTION_FAILED,
            Self::HashingFailed(_) => ffi::status::HASHING_FAILED,
            Self::HmacFailed(_) => ffi::status::HMAC_FAILED,
            Self::HkdfFailed(_) => ffi::status::HKDF_FAILED,
            Self::KeyOperationFailed(_) => ffi::status::KEY_FAILED,
            Self::SignatureFailed(_) => ffi::status::SIGNATURE_FAILED,
            Self::AgreementFailed(_) => ffi::status::AGREEMENT_FAILED,
            Self::Unknown { code, .. } => *code,
        }
    }

    /// Human-readable description from the Swift bridge.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::InvalidArgument(message)
            | Self::EncryptionFailed(message)
            | Self::DecryptionFailed(message)
            | Self::HashingFailed(message)
            | Self::HmacFailed(message)
            | Self::HkdfFailed(message)
            | Self::KeyOperationFailed(message)
            | Self::SignatureFailed(message)
            | Self::AgreementFailed(message)
            | Self::Unknown { message, .. } => message,
        }
    }
}

impl fmt::Display for CryptoKitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (code {})", self.message(), self.code())
    }
}

impl std::error::Error for CryptoKitError {}

/// Take ownership of a Swift-allocated C string and free it with `libc::free`.
fn take_owned_c_string(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }

    let string = unsafe { core::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { free(ptr.cast()) };
    string
}

/// Take ownership of a Swift-allocated byte buffer and free it with `libc::free`.
pub(crate) fn take_owned_buffer(ptr: *mut u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        if !ptr.is_null() {
            unsafe { free(ptr.cast()) };
        }
        return Vec::new();
    }

    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
    unsafe { free(ptr.cast()) };
    bytes
}

/// Build a `CryptoKitError` from a Swift status code and optional message.
pub(crate) fn from_swift(status: i32, error_str: *mut c_char) -> CryptoKitError {
    let message = take_owned_c_string(error_str);
    from_status_message(status, message)
}

/// Build a `CryptoKitError` from a status code and message generated in Rust.
#[must_use]
pub const fn from_status_message(status: i32, message: String) -> CryptoKitError {
    match status {
        ffi::status::INVALID_ARGUMENT => CryptoKitError::InvalidArgument(message),
        ffi::status::ENCRYPTION_FAILED => CryptoKitError::EncryptionFailed(message),
        ffi::status::DECRYPTION_FAILED => CryptoKitError::DecryptionFailed(message),
        ffi::status::HASHING_FAILED => CryptoKitError::HashingFailed(message),
        ffi::status::HMAC_FAILED => CryptoKitError::HmacFailed(message),
        ffi::status::HKDF_FAILED => CryptoKitError::HkdfFailed(message),
        ffi::status::KEY_FAILED => CryptoKitError::KeyOperationFailed(message),
        ffi::status::SIGNATURE_FAILED => CryptoKitError::SignatureFailed(message),
        ffi::status::AGREEMENT_FAILED => CryptoKitError::AgreementFailed(message),
        code => CryptoKitError::Unknown { code, message },
    }
}
