#!/bin/sh
# Test all Rust crates

set -e

export LSAN_OPTIONS=suppressions=${abs_top_srcdir}/src/test/rust_supp.txt

for cargo_toml_dir in "${abs_top_srcdir:-../../..}"/src/rust/*; do
    if [ -e "${cargo_toml_dir}/Cargo.toml" ]; then
	cd "${cargo_toml_dir}" && \
	    CARGO_TARGET_DIR="${abs_top_builddir:-../../..}/src/rust/target" \
	    CARGO_HOME="${abs_top_builddir:-../../..}/src/rust/.cargo" \
	    "${CARGO:-cargo}" test ${CARGO_ONLINE-"--frozen"} \
	    ${EXTRA_CARGO_OPTIONS} \
	    --manifest-path "${cargo_toml_dir}/Cargo.toml" || exitcode=1
    fi
done

exit $exitcode
