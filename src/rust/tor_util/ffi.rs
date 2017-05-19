//! FFI functions, only to be called from C.
//!
//! Equivalent C versions of these live in `src/common/compat_rust.c`

use std::mem::forget;
use std::ffi::CString;

use libc;
use rust_string::RustString;

/// Free the passed `RustString` (`rust_str_t` in C), to be used in place of
/// `tor_free`().
///
/// # Examples
/// ```c
/// rust_str_t r_s = rust_welcome_string();
/// rust_str_free(r_s);
/// ```
#[no_mangle]
#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
pub unsafe extern "C" fn rust_str_free(_str: RustString) {
    // Empty body: Just drop _str and we're done (Drop takes care of it).
}

/// Lends an immutable, NUL-terminated C String.
///
/// # Examples
/// ```c
/// rust_str_t r_s = rust_welcome_string();
/// const char *s = rust_str_get(r_s);
/// printf("%s", s);
/// rust_str_free(r_s);
/// ```
#[no_mangle]
pub unsafe extern "C" fn rust_str_get(str: RustString) -> *const libc::c_char {
    let res = str.as_ptr();
    forget(str);
    res
}

/// Returns a short string to announce Rust support during startup.
///
/// # Examples
/// ```c
/// rust_str_t r_s = rust_welcome_string();
/// const char *s = rust_str_get(r_s);
/// printf("%s", s);
/// rust_str_free(r_s);
/// ```
#[no_mangle]
pub extern "C" fn rust_welcome_string() -> RustString {
    let s = CString::new("Tor is running with Rust integration. Please report \
                          any bugs you encouter.")
            .unwrap();
    RustString::from(s)
}
