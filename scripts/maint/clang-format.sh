#!/bin/sh
# Copyright 2020, The Tor Project, Inc.
# See LICENSE for licensing information.

#
# DO NOT COMMIT OR MERGE CODE THAT IS RUN THROUGH THIS TOOL YET.
#
# WE ARE STILL DISCUSSING OUR DESIRED STYLE AND ITERATING ON IT.
#     (12 Feb 2020)
#

# This script runs "clang-format" and "codetool" in sequence over each of
# our source files, and replaces the original file only if it has changed.
#
# We can't just use clang-format -i, since we also want to use codetool to
# reformat a few things back to how we want them, and we want avoid changing
# the mtime on files that didn't actually change.

set -e

cd "$(dirname "$0")/../../src/"

# Shellcheck complains that a for loop over find's output is unreliable,
# since there might be special characters in the output.  But we happen
# to know that none of our C files have special characters or spaces in
# their names, so this is safe.
#
# shellcheck disable=SC2044
for fname in $(find lib core feature app test tools -name '[^.]*.[ch]'); do
    tmpfname="${fname}.clang_fmt.tmp"
    rm -f "${tmpfname}"
    clang-format --style=file "${fname}" > "${tmpfname}"
    ../scripts/maint/codetool.py "${tmpfname}"
    if cmp "${fname}" "${tmpfname}" >/dev/null 2>&1; then
        echo "No change in ${fname}"
        rm -f "${tmpfname}"
    else
        echo "Change in ${fname}"
        mv "${tmpfname}" "${fname}"
    fi
done
