#!/bin/sh
# Test all the Rust crates we're using

crates=tor_util

exitcode=0

for crate in $crates; do
    cd "${abs_top_srcdir:-.}/src/rust/${crate}"
    CARGO_TARGET_DIR="${abs_top_builddir}/src/rust/target" CARGO_HOME="${abs_top_builddir}/src/rust" "${CARGO:-cargo}" test ${CARGO_ONLINE-"--frozen"} || exitcode=1
done

exit $exitcode
