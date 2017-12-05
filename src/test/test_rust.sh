#!/bin/sh
# Test all Rust crates

crates="protover tor_util smartlist tor_allocate"

exitcode=0

set -e

for crate in $crates; do
    cd "${abs_top_builddir:-../../..}/src/rust"
    CARGO_TARGET_DIR="${abs_top_builddir:-../../..}/src/rust/target" \
      CARGO_HOME="${abs_top_builddir:-../../..}/src/rust" \
      "${CARGO:-cargo}" test ${CARGO_ONLINE-"--frozen"} \
      --manifest-path "${abs_top_srcdir:-.}/src/rust/${crate}/Cargo.toml" \
	|| exitcode=1
    cd -
done

exit $exitcode
