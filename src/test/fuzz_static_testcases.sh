#!/bin/sh

# Copyright (c) 2016, The Tor Project, Inc.
# See LICENSE for licensing information

set -e

for fuzzer in "${builddir:-.}"/src/test/fuzz/fuzz-* ; do
    f=`basename $fuzzer`
    case="${f#fuzz-}"
    echo "Running tests for ${case}"
    for entry in ${abs_top_srcdir:-.}/src/test/fuzz/data/${case}/*; do
	"${fuzzer}" "--err" < "$entry"
    done
done
