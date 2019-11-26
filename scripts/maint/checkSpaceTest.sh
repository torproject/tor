#!/bin/sh
# Copyright 2019, The Tor Project, Inc.
# See LICENSE for licensing information

# Integration test for checkSpace.pl, which we want to rewrite.

umask 077
set -e

# make a safe space for temporary files
DATA_DIR=$(mktemp -d -t tor_checkspace_tests.XXXXXX)
trap 'rm -rf "$DATA_DIR"' 0

RECEIVED_FNAME="${DATA_DIR}/got.txt"

cd "$(dirname "$0")/checkspace_tests"

# we expect this to give an error code.
../checkSpace.pl -C ./*.[ch] ./*/*.[ch] > "${RECEIVED_FNAME}" && exit 1

diff -u expected.txt "${RECEIVED_FNAME}" || exit 1

echo "OK"
