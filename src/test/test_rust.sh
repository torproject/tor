#!/bin/sh
# Test all Rust crates

set -e


for cargo_toml in "${abs_top_srcdir:-../../..}"/src/rust/*/Cargo.toml; do
    CARGO_TARGET_DIR="${abs_top_builddir:-../../..}/src/rust/target" \
    CARGO_HOME="${abs_top_builddir:-../../..}/src/rust" \
    "${CARGO:-cargo}" test --all-features ${CARGO_ONLINE-"--frozen"} \
    --manifest-path "$cargo_toml" || exitcode=1
done

exit $exitcode


