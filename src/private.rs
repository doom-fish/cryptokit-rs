use core::ffi::{c_char, c_void};
use std::fmt::Write as _;
use std::ptr;
use std::ptr::NonNull;

use crate::error::{from_status_message, from_swift, take_owned_buffer, CryptoKitError, Result};
use crate::ffi;

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let difference = left
        .iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            core::hint::black_box(difference | (left ^ right))
        });
    difference == 0
}

pub fn validate_byte_count(type_name: &str, expected: usize, bytes: Vec<u8>) -> Result<Vec<u8>> {
    let actual = bytes.len();
    if actual == expected {
        Ok(bytes)
    } else {
        Err(CryptoKitError::InvalidArgument(format!(
            "{type_name} expects {expected} bytes, got {actual}"
        )))
    }
}

pub fn bridge_status<F>(call: F) -> Result<()>
where
    F: FnOnce(*mut *mut c_char) -> i32,
{
    let mut error = ptr::null_mut();

    let status = call(&mut error);
    if status != ffi::status::OK {
        return Err(from_swift(status, error));
    }

    Ok(())
}

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

pub fn bridge_optional_bytes<F>(call: F) -> Result<Option<Vec<u8>>>
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

    if out.is_null() && out_len == 0 {
        Ok(None)
    } else {
        Ok(Some(take_owned_buffer(out, out_len)))
    }
}

pub fn bridge_two_buffers<F>(call: F) -> Result<(Vec<u8>, Vec<u8>)>
where
    F: FnOnce(*mut *mut u8, *mut usize, *mut *mut u8, *mut usize, *mut *mut c_char) -> i32,
{
    let mut first = ptr::null_mut();
    let mut first_len = 0_usize;
    let mut second = ptr::null_mut();
    let mut second_len = 0_usize;
    let mut error = ptr::null_mut();

    let status = call(
        &mut first,
        &mut first_len,
        &mut second,
        &mut second_len,
        &mut error,
    );
    if status != ffi::status::OK {
        return Err(from_swift(status, error));
    }

    Ok((
        take_owned_buffer(first, first_len),
        take_owned_buffer(second, second_len),
    ))
}

pub fn bridge_handle<F>(call: F) -> Result<NonNull<c_void>>
where
    F: FnOnce(*mut *mut c_void, *mut *mut c_char) -> i32,
{
    let mut handle = ptr::null_mut();
    let mut error = ptr::null_mut();

    let status = call(&mut handle, &mut error);
    if status != ffi::status::OK {
        return Err(from_swift(status, error));
    }

    NonNull::new(handle).ok_or_else(|| {
        from_status_message(
            ffi::status::UNKNOWN,
            "Swift bridge returned no handle".to_owned(),
        )
    })
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
