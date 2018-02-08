// Copyright (c) 2016-2017, The Tor Project, Inc. */
// See LICENSE for licensing information */

//! Utilities for working with static strings.

use std::ffi::CStr;

/// A byte-array containing a single NUL byte (`b"\0"`).
pub const NUL_BYTE: &'static [u8] = b"\0";

/// Determine if a byte slice is a C-like string.
///
/// These checks guarantee that:
///
/// 1. there are no intermediate NUL bytes
/// 2. the last byte *is* a NUL byte
///
/// # Warning
///
/// This function does _not_ guarantee that the bytes represent any valid
/// encoding such as ASCII or UTF-8.
///
/// # Examples
///
/// ```
/// # use tor_util::strings::byte_slice_is_c_like;
/// #
/// let bytes: &[u8] = b"foo bar baz";
///
/// assert!(byte_slice_is_c_like(&bytes) == false);
///
/// let bytes: &[u8] = b"foo\0bar baz";
///
/// assert!(byte_slice_is_c_like(&bytes) == false);
///
/// let bytes: &[u8] = b"foo bar baz\0";
///
/// assert!(byte_slice_is_c_like(&bytes) == true);
/// ```
pub fn byte_slice_is_c_like(bytes: &[u8]) -> bool {
    if !bytes[..bytes.len() - 1].contains(&0x00) && bytes[bytes.len() - 1] == 0x00 {
        return true;
    }
    false
}

/// Get a static `CStr` containing a single `NUL_BYTE`.
///
/// # Examples
///
/// When used as follows in a Rust FFI function, which could be called
/// from C:
///
/// ```
/// # extern crate libc;
/// # extern crate tor_util;
/// #
/// # use tor_util::strings::empty_static_cstr;
/// use libc::c_char;
/// use std::ffi::CStr;
///
/// pub extern "C" fn give_c_code_an_empty_static_string() -> *const c_char {
///     let empty: &'static CStr = empty_static_cstr();
///
///     empty.as_ptr()
/// }
///
/// # fn main() {
/// #     give_c_code_an_empty_static_string();
/// # }
/// ```
///
/// This equates to an "empty" `const char*` static string in C.
pub fn empty_static_cstr() -> &'static CStr {
    let empty: &'static CStr;

    unsafe {
        empty = CStr::from_bytes_with_nul_unchecked(NUL_BYTE);
    }

    empty
}
