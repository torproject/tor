// Copyright (c) 2018, The Tor Project, Inc.
// Copyright (c) 2018, isis agora lovecruft
// See LICENSE for licensing information

//! Bindings to external (P)RNG interfaces and utilities in 
//! src/common/crypto_rand.[ch].
//!
//! We wrap our C implementations in src/common/crypto_rand.[ch] here in order
//! to provide wrappers with native Rust types, and then provide more Rusty
//! types and and trait implementations in src/rust/crypto/rand/.

use std::time::Duration;

use libc::c_char;
use libc::c_double;
use libc::c_int;
use libc::c_uint;
use libc::c_void;
use libc::size_t;
use libc::time_t;
use libc::uint8_t;
use libc::uint64_t;

extern "C" {
    fn crypto_seed_rng() -> c_int;
    fn crypto_strongest_rand(out: *mut uint8_t, out_len: size_t);
    fn crypto_rand_time_range(min: time_t, max: time_t) -> time_t;
    fn crypto_rand_double() -> c_double;
    // fn crypto_random_hostname(min_rand_len: c_int, max_rand_len: c_int,
    //                           prefix: *const c_char, suffix: *const c_char) -> *mut c_char;
}

/// Seed OpenSSL's random number generator with bytes from the operating
/// system.
///
/// # Returns
///
/// `true` on success; `false` on failure.
pub fn c_tor_crypto_seed_rng() -> bool {
    let ret: c_int;

    unsafe {
        ret = crypto_seed_rng();
    }
    match ret {
        0 => return true,
        _ => return false,
    }
}

/// Fill the bytes of `dest` with strong random data.
pub fn c_tor_crypto_strongest_rand(dest: &mut [u8]) {
    // We'll let the C side panic if the len is larger than
    // MAX_STRONGEST_RAND_SIZE, rather than potentially panicking here.  A
    // paranoid caller should assert on the length of dest *before* calling this
    // function.
    unsafe {
        crypto_strongest_rand(dest.as_mut_ptr(), dest.len() as size_t);
    }
}

/// Get a random time, in seconds since the Unix Epoch.
///
/// # Returns
///
/// A `std::time::Duration` of seconds since the Unix Epoch.
pub fn c_tor_crypto_rand_time_range(min: &Duration, max: &Duration) -> Duration {
    let ret: time_t;

    unsafe {
        ret = crypto_rand_time_range(min.as_secs() as time_t, max.as_secs() as time_t);
    }

    Duration::from_secs(ret as u64)
}

/// Return a pseudorandom 64-bit float, chosen uniformly from the range [0.0, 1.0).
pub fn c_tor_crypto_rand_double() -> f64 {
    unsafe {
        crypto_rand_double()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_layout_tor_weak_rng_t() {
        assert_eq!(::std::mem::size_of::<tor_weak_rng_t>(), 0usize,
                   concat!("Size of: ", stringify!(tor_weak_rng_t)));
        assert_eq!(::std::mem::align_of::<tor_weak_rng_t>(), 1usize,
                   concat!("Alignment of ", stringify!(tor_weak_rng_t)));
    }
}
