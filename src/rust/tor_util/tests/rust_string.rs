extern crate tor_util;
extern crate libc;

use std::ffi::CString;
use tor_util::RustString;

#[test]
fn rust_string_conversions_preserve_c_string() {
    let s = CString::new("asdf foo").unwrap();
    let r = RustString::from(s.clone());
    let r2 = RustString::from(s.clone());
    let c = r2.as_ptr();
    assert_eq!(unsafe { libc::strlen(c) }, 8);
    let c_str = r.into();
    assert_eq!(s, c_str);
}

#[test]
fn empty_string() {
    let s = CString::new("").unwrap();
    let r = RustString::from(s.clone());
    let c = r.as_ptr();
    assert_eq!(unsafe { libc::strlen(c) }, 0);
    let c_str = r.into();
    assert_eq!(s, c_str);
}

#[test]
fn c_string_with_unicode() {
    // The euro sign is three bytes
    let s = CString::new("asd€asd").unwrap();
    let r = RustString::from(s.clone());
    let c = r.as_ptr();
    assert_eq!(unsafe { libc::strlen(c) }, 9);
    let c_str = r.into();
    assert_eq!(s, c_str);
}
