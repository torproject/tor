#!/bin/sh
# Test all the Rust crates we're using

crates=tor_util

exitcode=0

for crate in $crates; do
    cd "${abs_top_srcdir:-.}/src/rust/${crate}"
    "${CARGO:-cargo}" test --frozen || exitcode=1
done

exit $exitcode
