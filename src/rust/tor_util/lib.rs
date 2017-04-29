//! C <-> Rust compatibility helpers and types.
//!
//! Generically useful, small scale helpers should go here. This goes for both
//! the C side (in the form of the ffi module) as well as the Rust side
//! (individual modules per functionality). The corresponding C stuff lives in
//! `src/common/compat_rust.{c,h}`.

extern crate libc;

mod rust_string;
pub mod ffi;

pub use rust_string::*;
