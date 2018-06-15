// Copyright (c) 2018, The Tor Project, Inc.
// Copyright (c) 2018, isis agora lovecruft
// See LICENSE for licensing information

//! Common cryptographic functions and utilities.
//!
//! # Hash Digests and eXtendable Output Functions (XOFs)
//!
//! The `digests` module contains submodules for specific hash digests
//! and extendable output functions.
//!
//! ```
//! use crypto::digests::sha256::Sha256;
//!
//! let hasher: Sha256 = Sha256::default();
//! let mut result: [u8; 32] = [0u8; 32];
//!
//! hasher.input("foo");
//! hasher.input("bar");
//! hasher.input("baz");
//!
//! result.copy_from_slice(hasher.result().as_bytes());
//!
//! assert!(result == "XXX");
//! ```

#[deny(missing_docs)]

// External crates from cargo or TOR_RUST_DEPENDENCIES.
extern crate digest;
extern crate libc;

// Our local crates.
extern crate external;

pub mod digests;  // Unfortunately named "digests" plural to avoid name conflict with the digest crate
pub mod rand;

