// Copyright (c) 2016-2017, The Tor Project, Inc. */
// See LICENSE for licensing information */

//! FFI functions to announce Rust support during tor startup, only to be
//! called from C.
//!

use libc::c_char;
use tor_allocate::allocate_and_copy_string;

/// Returns a short string to announce Rust support during startup.
///
/// # Examples
/// ```c
/// char *rust_str = rust_welcome_string();
/// printf("%s", rust_str);
/// tor_free(rust_str);
/// ```
#[no_mangle]
pub extern "C" fn rust_welcome_string() -> *mut c_char {
    let rust_welcome = String::from(
        "Tor is running with Rust integration. Please report \
         any bugs you encounter.",
    );
    allocate_and_copy_string(&rust_welcome)
}
