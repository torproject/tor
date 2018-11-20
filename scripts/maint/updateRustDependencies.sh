#!/usr/bin/env bash
#
# Copyright (c) 2018 The Tor Project, Inc.
# Copyright (c) 2018 isis agora lovecruft
# See LICENSE for license information
#
# updateRustDependencies.sh
# -------------------------
# Update our vendored Rust dependencies, either adding/removing
# dependencies and/or upgrading current dependencies to newer
# versions.
#
# To use this script, first add your dependencies, exactly specifying
# their versions, into the appropriate *crate-level* Cargo.toml in
# src/rust/ (i.e. *not* /src/rust/Cargo.toml, but instead the one for
# your crate).
#
# Next, run this script.  Then, go into src/ext/rust and commit the
# changes to the tor-rust-dependencies repo.

set -e

HERE=$(dirname "$(realpath "$0")")
TOPLEVEL=$(dirname "$(dirname "$HERE")")
TOML="$TOPLEVEL/src/rust/Cargo.toml"
VENDORED="$TOPLEVEL/src/ext/rust/crates"
CARGO=$(command -v cargo)

if ! test -f "$TOML"  ; then
    printf "Error: Couldn't find workspace Cargo.toml in expected location: %s\\n" "$TOML"
fi

if ! test -d "$VENDORED" ; then
    printf "Error: Couldn't find directory for Rust dependencies! Expected location: %s\\n" "$VENDORED"
fi

if test -z "$CARGO" ; then
    printf "Error: cargo must be installed and in your \$PATH\\n"
fi

if test -z "$(cargo --list | grep vendor)" ; then
    printf "Error: cargo-vendor not installed\\n"
fi

$CARGO vendor -v --locked --explicit-version --no-delete --sync "$TOML" "$VENDORED"
