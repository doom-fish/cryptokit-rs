//! Symmetric keys.

use core::fmt;

use zeroize::Zeroizing;

use crate::error::Result;
use crate::ffi;
use crate::private::{bridge_bytes, constant_time_eq};

/// Supported symmetric-key sizes for generated keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SymmetricKeySize {
    Bits128,
    Bits192,
    Bits256,
}

impl SymmetricKeySize {
    pub(crate) const fn as_ffi(self) -> i32 {
        match self {
            Self::Bits128 => 128,
            Self::Bits192 => 192,
            Self::Bits256 => 256,
        }
    }
}

/// Opaque symmetric key material stored as raw bytes.
#[derive(Clone)]
pub struct SymmetricKey {
    bytes: Zeroizing<Vec<u8>>,
}

impl SymmetricKey {
    /// Generate a fresh symmetric key of the requested size.
    ///
    /// # Errors
    ///
    /// Returns an error if the `CryptoKit` bridge rejects the request.
    pub fn generate(size: SymmetricKeySize) -> Result<Self> {
        let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_symmetric_key_generate(size.as_ffi(), out, out_len, error_out)
        })?;
        Ok(Self::from_bytes(bytes))
    }

    /// Wrap existing symmetric key bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes.into()),
        }
    }

    /// Borrow the underlying key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the key and return its underlying bytes.
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }

    /// Length of the key in bits.
    #[must_use]
    pub fn bits(&self) -> usize {
        self.bytes.len() * 8
    }
}

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.bytes, &other.bytes)
    }
}

impl Eq for SymmetricKey {}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("bits", &self.bits())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::SymmetricKey;

    #[test]
    fn symmetric_keys_redact_debug_and_compare_by_value() {
        let key = SymmetricKey::from_bytes(vec![0xab; 32]);
        assert_eq!(format!("{key:?}"), "SymmetricKey { bits: 256, .. }");
        assert_eq!(key, SymmetricKey::from_bytes(vec![0xab; 32]));
        assert_ne!(key, SymmetricKey::from_bytes(vec![0xab; 16]));

        let mut different = vec![0xab; 32];
        different[31] = 0xac;
        assert_ne!(key, SymmetricKey::from_bytes(different));
        assert_eq!(key.clone().into_bytes().as_slice(), key.as_bytes());
    }
}
