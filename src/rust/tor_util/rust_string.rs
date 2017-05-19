use std::ffi::CString;
use std::mem::forget;
use libc;

/// Compatibility wrapper for strings allocated in Rust and passed to C.
///
/// Rust doesn't ensure the safety of freeing memory across an FFI boundary, so
/// we need to take special care to ensure we're not accidentally calling
/// `tor_free`() on any string allocated in Rust. To more easily differentiate
/// between strings that possibly (if Rust support is enabled) were allocated
/// in Rust, C has the `rust_str_t` helper type. The equivalent on the Rust
/// side is `RustString`.
///
/// Note: This type must not be used for strings allocated in C.
#[repr(C)]
#[derive(Debug)]
pub struct RustString(*mut libc::c_char);

impl RustString {
    /// Returns a pointer to the underlying NUL-terminated byte array.
    ///
    /// Note that this function is not typically useful for Rust callers,
    /// except in a direct FFI context.
    ///
    /// # Examples
    /// ```
    /// # use tor_util::RustString;
    /// use std::ffi::CString;
    ///
    /// let r = RustString::from(CString::new("asdf").unwrap());
    /// let c_str = r.as_ptr();
    /// assert_eq!(b'a', unsafe { *c_str as u8});
    /// ```
    pub fn as_ptr(&self) -> *const libc::c_char {
        self.0 as *const libc::c_char
    }
}

impl From<CString> for RustString {
    /// Constructs a new `RustString`
    ///
    /// # Examples
    /// ```
    /// # use tor_util::RustString;
    /// use std::ffi::CString;
    ///
    /// let r = RustString::from(CString::new("asdf").unwrap());
    /// ```
    fn from(str: CString) -> RustString {
        RustString(str.into_raw())
    }
}

impl Into<CString> for RustString {
    /// Reconstructs a `CString` from this `RustString`.
    ///
    /// Useful to take ownership back from a `RustString` that was given to C
    /// code.
    ///
    /// # Examples
    /// ```
    /// # use tor_util::RustString;
    /// use std::ffi::CString;
    ///
    /// let cs = CString::new("asdf").unwrap();
    /// let r = RustString::from(cs.clone());
    /// let cs2 = r.into();
    /// assert_eq!(cs, cs2);
    /// ```
    fn into(self) -> CString {
        // Calling from_raw is always OK here: We only construct self using
        // valid CStrings and don't expose anything that could mutate it
        let ret = unsafe { CString::from_raw(self.0) };
        forget(self);
        ret
    }
}

impl Drop for RustString {
    fn drop(&mut self) {
        // Don't use into() here, because we would need to move out of
        // self. Same safety consideration. Immediately drop the created
        // CString, which takes care of freeing the wrapped string.
        unsafe { CString::from_raw(self.0) };
    }
}

#[cfg(test)]
mod test {
    use std::mem;
    use super::*;

    use libc;

    /// Ensures we're not adding overhead by using RustString.
    #[test]
    fn size_of() {
        assert_eq!(mem::size_of::<*mut libc::c_char>(),
                   mem::size_of::<RustString>())
    }
}
