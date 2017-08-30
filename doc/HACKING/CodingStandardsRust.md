
 Rust Coding Standards
=======================

You MUST follow the standards laid out in `.../doc/HACKING/CodingStandards.md`,
where applicable.

 Module/Crate Declarations
---------------------------

Each Tor C module which is being rewritten MUST be in its own crate.
See the structure of `.../src/rust` for examples.

In your crate, you MUST use `lib.rs` ONLY for pulling in external
crates (e.g. `extern crate libc;`) and exporting public objects from
other Rust modules (e.g. `pub use mymodule::foo;`).  For example, if
you create a crate in `.../src/rust/yourcrate`, your Rust code should
live in `.../src/rust/yourcrate/yourcode.rs` and the public interface
to it should be exported in `.../src/rust/yourcrate/lib.rs`.

If your code is to be called from Tor C code, you MUST define a safe
`ffi.rs`.  See the "Safety" section further down for more details.

For example, in a hypothetical `tor_addition` Rust module:

In `.../src/rust/tor_addition/addition.rs`:

    pub fn get_sum(a: i32, b: i32) -> i32 {
        a + b
    }

In `.../src/rust/tor_addition/lib.rs`:

    pub use addition::*;

In `.../src/rust/tor_addition/ffi.rs`:

    #[no_mangle]
    pub extern "C" fn tor_get_sum(a: c_int, b: c_int) -> c_int {
        get_sum(a, b)
    }

If your Rust code must call out to parts of Tor's C code, you must
declare the functions you are calling in the `external` crate, located
at `.../src/rust/external`.

XXX get better examples of how to declare these externs, when/how they
XXX are unsafe, what they are expected to do —isis

Modules should strive to be below 500 lines (tests excluded). Single
responsibility and limited dependencies should be a guiding standard.

If you have any external modules as dependencies (e.g. `extern crate
libc;`), you MUST declare them in your crate's `lib.rs` and NOT in any
other module.

 Dependencies
--------------

In general, we use modules from only the Rust standard library
whenever possible. We will review including external crates on a
case-by-case basis.

 Documentation
---------------

You MUST include `#[deny(missing_docs)]` in your crate.

For function/method comments, you SHOULD include a one-sentence, "first person"
description of function behaviour (see requirements for documentation as
described in `.../src/HACKING/CodingStandards.md`), then an `# Inputs` section
for inputs or initialisation values, a `# Returns` section for return
values/types, a `# Warning` section containing warnings for unsafe behaviours or
panics that could happen.  For publicly accessible
types/constants/objects/functions/methods, you SHOULD also include an
`# Examples` section with runnable doctests.

You MUST document your module with _module docstring_ comments,
i.e. `//!` at the beginning of each line.

 Testing
---------

All code MUST be unittested and integration tested.

Public functions/objects exported from a crate SHOULD include doctests
describing how the function/object is expected to be used.

Integration tests SHOULD go into a `tests/` directory inside your
crate.  Unittests SHOULD go into their own module inside the module
they are testing, e.g. in `.../src/rust/tor_addition/addition.rs` you
should put:

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn addition_with_zero() {
            let sum: i32 = get_sum(5i32, 0i32);
            assert_eq!(sum, 5);
        }
    }

 Benchmarking
--------------

The external `test` crate can be used for most benchmarking.  However, using
this crate requires nightly Rust.  Since we may want to switch to a more
stable Rust compiler eventually, we shouldn't do things which will automatically
break builds for stable compilers.  Therefore, you MUST feature-gate your
benchmarks in the following manner.

If you wish to benchmark some of your Rust code, you MUST put the
following in the `[features]` section of your crate's `Cargo.toml`:

    [features]
    bench = []

Next, in your crate's `lib.rs` you MUST put:

    #[cfg(all(test, feature = "bench"))]
    extern crate test;

This ensures that the external crate `test`, which contains utilities
for basic benchmarks, is only used when running benchmarks via `cargo
bench --features bench`.

Finally, to write your benchmark code, in
`.../src/rust/tor_addition/addition.rs` you SHOULD put:

    #[cfg(all(test, features = "bench"))]
    mod bench {
        use test::Bencher;
        use super::*;

        #[bench]
        fn addition_small_integers(b: &mut Bencher) {
            b.iter(| | get_sum(5i32, 0i32));
        }
    }

 Fuzzing
---------

If you wish to fuzz parts of your code, please see the
[`cargo fuzz`](https://github.com/rust-fuzz/cargo-fuzz) crate, which uses
[libfuzzer-sys](https://github.com/rust-fuzz/libfuzzer-sys).

 Safety
--------

You SHOULD read [the nomicon](https://doc.rust-lang.org/nomicon/) before writing
Rust FFI code.  It is *highly advised* that you read and write normal Rust code
before attempting to write FFI or any other unsafe code.

Here are some additional bits of advice and rules:

1. `unwrap()`

   If you call `unwrap()`, anywhere, even in a test, you MUST include
   an inline comment stating how the unwrap will either 1) never fail,
   or 2) should fail (i.e. in a unittest).

2. `unsafe`

   If you use `unsafe`, you MUST describe a contract in your
   documentation which describes how and when the unsafe code may
   fail, and what expectations are made w.r.t. the interfaces to
   unsafe code.  This is also REQUIRED for major pieces of FFI between
   C and Rust.

   When creating an FFI in Rust for C code to call, it is NOT REQUIRED
   to declare the entire function `unsafe`.  For example, rather than doing:

        #[no_mangle]
        pub unsafe extern "C" fn increment_and_combine_numbers(mut numbers: [u8; 4]) -> u32 {
            for index in 0..numbers.len() {
                numbers[index] += 1;
            }
            std::mem::transmute::<[u8; 4], u32>(numbers)
        }

   You SHOULD instead do:

        #[no_mangle]
        pub extern "C" fn increment_and_combine_numbers(mut numbers: [u8; 4]) -> u32 {
            for index in 0..numbers.len() {
                numbers[index] += 1;
            }
            unsafe {
                std::mem::transmute::<[u8; 4], u32>(numbers)
            }
        }

3. Pass only integer types and bytes over the boundary

   The only non-integer type which may cross the FFI boundary is
   bytes, e.g. `&[u8]`.  This SHOULD be done on the Rust side by
   passing a pointer (`*mut libc::c_char`) and a length
   (`libc::size_t`).

   One might be tempted to do this via doing
   `CString::new("blah").unwrap().into_raw()`. This has several problems:

   a) If you do `CString::new("bl\x00ah")` then the unwrap() will fail
      due to the additional NULL terminator, causing a dangling
      pointer to be returned (as well as a potential use-after-free).

   b) Returning the raw pointer will cause the CString to run its deallocator,
      which causes any C code which tries to access the contents to dereference a
      NULL pointer.

   c) If we were to do `as_raw()` this would result in a potential double-free
      since the Rust deallocator would run and possibly Tor's deallocator.

   d) Calling `into_raw()` without later using the same pointer in Rust to call
      `from_raw()` and then deallocate in Rust can result in a
      [memory leak](https://doc.rust-lang.org/std/ffi/struct.CString.html#method.into_raw).

     [It was determined](https://github.com/rust-lang/rust/pull/41074) that this
     is safe to do if you use the same allocator in C and Rust and also specify
     the memory alignment for CString (except that there is no way to specify
     the alignment for CString).  It is believed that the alignment is always 1,
     which would mean it's safe to dealloc the resulting `*mut c_char` in Tor's
     C code.  However, the Rust developers are not willing to guarantee the
     stability of, or a contract for, this behaviour, citing concerns that this
     is potentially extremely and subtly unsafe.


4. Perform an allocation on the other side of the boundary

   After crossing the boundary, the other side MUST perform an
   allocation to copy the data and is therefore responsible for
   freeing that memory later.

5. No touching other language's enums

   Rust enums should never be touched from C (nor can they be safely
   `#[repr(C)]`) nor vice versa:

   >  "The chosen size is the default enum size for the target platform's C
   >  ABI. Note that enum representation in C is implementation defined, so this is
   >  really a "best guess". In particular, this may be incorrect when the C code
   >  of interest is compiled with certain flags."

   (from https://gankro.github.io/nomicon/other-reprs.html)

6. Type safety

   Wherever possible and sensical, you SHOULD create new types in a
   manner which prevents type confusion or misuse.  For example,
   rather than using an untyped mapping between strings and integers
   like so:

        use std::collections::HashMap;

        pub fn get_elements_with_over_9000_points(map: &HashMap<String, usize>) -> Vec<String> {
            ...
        }

   It would be safer to define a new type, such that some other usage
   of `HashMap<String, usize>` cannot be confused for this type:

        pub struct DragonBallZPowers(pub HashMap<String, usize>);

        impl DragonBallZPowers {
            pub fn over_nine_thousand<'a>(&'a self) -> Vec<&'a String> {
                let mut powerful_enough: Vec<&'a String> = Vec::with_capacity(5);

                for (character, power) in &self.0 {
                    if *power > 9000 {
                        powerful_enough.push(character);
                    }
                }
                powerful_enough
            }
        }

   Note the following code, which uses Rust's type aliasing, is valid
   but it does NOT meet the desired type safety goals:

        pub type Power = usize;

        pub fn over_nine_thousand(power: &Power) -> bool {
            if *power > 9000 {
                return true;
            }
            false
        }

        // We can still do the following:
        let his_power: usize = 9001;
        over_nine_thousand(&his_power);

7. Unsafe mucking around with lifetimes

   Because lifetimes are technically, in type theory terms, a kind, i.e. a
   family of types, individual lifetimes can be treated as types.  For example,
   one can arbitrarily extend and shorten lifetime using `std::mem::transmute`:

        struct R<'a>(&'a i32);

        unsafe fn extend_lifetime<'b>(r: R<'b>) -> R<'static> {
            std::mem::transmute::<R<'b>, R<'static>>(r)
        }

        unsafe fn shorten_invariant_lifetime<'b, 'c>(r: &'b mut R<'static>) -> &'b mut R<'c> {
            std::mem::transmute::<&'b mut R<'static>, &'b mut R<'c>>(r)
        }

   Calling `extend_lifetime()` would cause an `R` passed into it to live forever
   for the life of the program (the `'static` lifetime).  Similarly,
   `shorten_invariant_lifetime()` could be used to take something meant to live
   forever, and cause it to disappear!  This is incredibly unsafe.  If you're
   going to be mucking around with lifetimes like this, first, you better have
   an extremely good reason, and second, you may as be honest and explicit about
   it, and for ferris' sake just use a raw pointer.

   In short, just because lifetimes can be treated like types doesn't mean you
   should do it.

8. Doing excessively unsafe things when there's a safer alternative

   Similarly to #7, often there are excessively unsafe ways to do a task and a
   simpler, safer way.  You MUST choose the safer option where possible.

   For example, `std::mem::transmute` can be abused in ways where casting with
   `as` would be both simpler and safer:

        // Don't do this
        let ptr = &0;
        let ptr_num_transmute = unsafe { std::mem::transmute::<&i32, usize>(ptr)};

        // Use an `as` cast instead
        let ptr_num_cast = ptr as *const i32 as usize;

   In fact, using `std::mem::transmute` for *any* reason is a code smell and as
   such SHOULD be avoided.


 Whitespace & Formatting
-------------------------

You MUST run `rustfmt` (https://github.com/rust-lang-nursery/rustfmt)
on your code before your code will be merged.  You can install rustfmt
by doing `cargo install rustfmt-nightly` and then run it with `cargo
fmt`.
