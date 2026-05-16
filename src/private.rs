use core::ffi::c_char;
use std::ptr;

use crate::error::{from_swift, take_owned_buffer, CryptoKitError, Result};
use crate::ffi;

pub fn bridge_bytes<F>(call: F) -> Result<Vec<u8>>
where
    F: FnOnce(*mut *mut u8, *mut usize, *mut *mut c_char) -> i32,
{
    let mut out = ptr::null_mut();
    let mut out_len = 0_usize;
    let mut error = ptr::null_mut();

    let status = call(&mut out, &mut out_len, &mut error);
    if status != ffi::status::OK {
        return Err(from_swift(status, error));
    }

    Ok(take_owned_buffer(out, out_len))
}

pub fn bridge_flag<F>(call: F) -> Result<bool>
where
    F: FnOnce(*mut u8, *mut *mut c_char) -> i32,
{
    let mut out = 0_u8;
    let mut error = ptr::null_mut();

    let status = call(&mut out, &mut error);
    if status != ffi::status::OK {
        return Err(from_swift(status, error));
    }

    Ok(out != 0)
}

pub fn ensure_same_algorithm<T>(left: T, right: T, kind: &str) -> Result<()>
where
    T: Copy + Eq,
{
    if left == right {
        Ok(())
    } else {
        Err(CryptoKitError::InvalidArgument(format!(
            "mismatched {kind} algorithms"
        )))
    }
}
