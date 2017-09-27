//! FFI functions, only to be called from C.
//!
//! This module provides the ability for C to free strings that have been
//! allocated in Rust.

extern crate libc;

use libc::c_char;
use std::ffi::CString;

/// This allows strings allocated in Rust to be freed in Rust. Every string
/// sent across the Rust/C FFI boundary should utilize this function for
/// freeing strings allocated in Rust.
#[no_mangle]
pub extern "C" fn free_rust_str(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { CString::from_raw(ptr) };
    }
}
