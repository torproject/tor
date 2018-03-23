#!/bin/sh
# Test all Rust crates

set -e

CARGO_TARGET_DIR="${abs_top_builddir:-../../..}/src/rust/target" \
    CARGO_HOME="${abs_top_builddir:-../../..}/src/rust" \
    find "${abs_top_srcdir:-../../..}/src/rust" \
    -mindepth 2 -maxdepth 2 \
    -type f -name 'Cargo.toml' \
    -exec "${CARGO:-cargo}" test --all-features ${CARGO_ONLINE-"--frozen"} \
    --manifest-path '{}' \;

exit $?

