//! Symmetric-key area helpers.

use crate::ffi;

pub use crate::symmetric::{SymmetricKey, SymmetricKeySize};

const BITS128_MASK: i32 = 1;
const BITS192_MASK: i32 = 1 << 1;
const BITS256_MASK: i32 = 1 << 2;

/// Return the symmetric-key sizes supported by the Swift bridge.
#[must_use]
pub fn supported_sizes() -> Vec<SymmetricKeySize> {
    let mask = unsafe { ffi::ck_symmetric_key_supported_size_mask() };
    let mut sizes = Vec::new();
    if mask & BITS128_MASK != 0 {
        sizes.push(SymmetricKeySize::Bits128);
    }
    if mask & BITS192_MASK != 0 {
        sizes.push(SymmetricKeySize::Bits192);
    }
    if mask & BITS256_MASK != 0 {
        sizes.push(SymmetricKeySize::Bits256);
    }
    sizes
}
