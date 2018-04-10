// Copyright (c) 2018, The Tor Project, Inc.
// Copyright (c) 2018, isis agora lovecruft
// See LICENSE for licensing information

//! Wrappers for Tor's pseudo-random number generator to provide implementations
//! of `rand_core` traits.

use rand_core::impls;
#[cfg(test)] use rand_core::CryptoRng;
use rand_core::Error;
use rand_core::RngCore;
use rand_core::SeedableRng;

/// A cryptographically-/insecure/ psuedo-random number generator based
/// on a mixed congruential generator.
///
/// Specifically the PRNG state, `X`, is mutated by the following
/// discontinuous linear equation:
///
/// ```text
/// X_{i} = (a X_{i-1} + b)   mod n
/// ```
///
/// where, in our case, we reuse the same parameters as OpenBSD and glibc,
/// `a=1103515245`, `b=12345`, and `n=2147483647`, which should produce a
/// maximal period over the range `0..u32::MAX`.
///
/// # Note
///
/// We reimplement the C here, rather than wrapping it, as it's one line of
/// pure-Rust code (meaning it can also trivially be used in Rust tests without
/// running into potential linker issues), as opposed to a few lines of `unsafe`
/// calls to C.
///
/// # Warning
///
/// This should hopefully go without saying, but this PRNG is completely
/// insecure and should never be used for anything an adversary should be unable
/// to predict.
//
// C_RUST_COUPLED: `tor_weak_rng_t` /src/common/util.c
pub struct TorInsecurePrng {
    state: u32,
}

impl SeedableRng for TorInsecurePrng {
    type Seed = [u8; 4];

    /// Create a new PRNG from a random 32-bit seed.
    //
    // C_RUST_COUPLED: `tor_init_weak_random()` /src/common/util.c
    fn from_seed(seed: Self::Seed) -> Self {
        let mut combined: u32 = seed[0].to_le() as u32;

        // Rather than using std::mem::transmute, we'll just bitwise-OR them
        // into each other.
        combined = (seed[1].to_le() as u32) << 8  | combined;
        combined = (seed[2].to_le() as u32) << 16 | combined;
        combined = (seed[2].to_le() as u32) << 24 | combined;

        TorInsecurePrng{ state: (combined & 0x7fffffff).to_le() }
    }
}

impl TorInsecurePrng {
    /// This is the equivalent function to `tor_weak_random()`.
    //
    // C_RUST_COUPLED: `tor_weak_random()` /src/common/util.c
    pub fn next_i32(&mut self) -> i32 {
        // The C code appears to purposefully overflow the 32-bit state integer.
        self.state = (self.state.wrapping_mul(1103515245).wrapping_add(12345) & 0x7fffffff).to_le();
        self.state as i32
    }
}


impl RngCore for TorInsecurePrng {
    // C_RUST_COUPLED: `tor_weak_random()` /src/common/util.c
    fn next_u32(&mut self) -> u32 {
        let x: u32 = self.next_i32() as u32;
        let y: u32 = self.next_i32() as u32;

        // We have to add two samples together due to modding 0x7fffffff
        x + y
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_u32(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}

/// If we're running tests, it's fine to pretend this PRNG is cryptographically
/// secure.  (This allows us to test which require an implementation of
/// `CryptoRng` without actually initialising all the OpenSSL C code.)
#[cfg(test)]
impl CryptoRng for TorInsecurePrng {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn next_u32_shouldnt_return_same_number_twice_in_a_row() {
        // This test will fail 1 out of 2^{64} times (5.42 e-20), but the
        // probability of a particle radiating off a star and hitting your RAM
        // is roughly 1.4 e-15 per byte of RAM per second, so if this fails,
        // blame ~~Cosmic Rays~~ and not anyone named isis.
        let mut prng: TorInsecurePrng = TorInsecurePrng::from_seed([0xDE, 0xAD, 0x15, 0x15]);

        let one: u32 = prng.next_u32();
        let two: u32 = prng.next_u32();

        assert!(one != two);
    }

    #[test]
    fn next_u32_should_have_uniform_distribution_average() {
        let mut prng: TorInsecurePrng = TorInsecurePrng::from_seed([0xDE, 0xAD, 0x15, 0x15]);
        let mut accumulator: Vec<u32> = Vec::new();
        let n: u64 = 10_000;

        for _ in 0 .. n as usize {
            accumulator.push(prng.next_u32());
        }
        let total: u64 = accumulator.iter().fold(0, |acc,&x| acc + (x as u64));
        let average = total / n;
        println!("average is {:?}", average);

        assert!(average <= 0x7fffffff + 0xf00000);
        assert!(average >= 0x7fffffff - 0xf00000);
    }

    #[test]
    fn next_u32_shouldnt_have_bit_bias() {
        // Since the modulus in the mixed congruential generator isn't a power
        // of two, the bits should not have any statistical bias.
        let mut prng: TorInsecurePrng = TorInsecurePrng::from_seed([0xDE, 0xAD, 0x15, 0x15]);
        let mut accumulator: Vec<u32> = Vec::new();
        let n: u64 = 10_000;

        for _ in 0 .. n as usize {
            accumulator.push(prng.next_u32().count_ones());
        }
        let total: u64 = accumulator.iter().fold(0, |acc,&x| acc + (x as u64));
        let average = total / n;
        println!("average is {:?}", average);

        assert!(average == 16);
    }

    #[test]
    fn next_u64_shouldnt_return_same_number_twice_in_a_row() {
        // This test will fail 1 out of 2^{128} times (2.94 e-39), but the
        // probability of a particle radiating off a star and hitting your RAM
        // is roughly 1.4 e-15 per byte of RAM per second, so if this fails,
        // blame ~~Cosmic Rays~~ and not anyone named isis.
        let mut prng: TorInsecurePrng = TorInsecurePrng::from_seed([0xDE, 0xAD, 0x15, 0x15]);

        let one: u64 = prng.next_u64();
        let two: u64 = prng.next_u64();

        assert!(one != two);
    }

    #[test]
    fn fill_bytes_shouldnt_leave_all_zeroes() {
        // Again, 1 in 256^8 (5.42 e-20) chances this fails.
        // ~~Cosmic Rays~~, I tell you.
        let mut prng: TorInsecurePrng = TorInsecurePrng::from_seed([0xDE, 0xAD, 0x15, 0x15]);
        let mut bytes: [u8; 8] = [0u8; 8];

        prng.fill_bytes(&mut bytes);

        assert!(bytes != [0u8; 8]);
    }
}
