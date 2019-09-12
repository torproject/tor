#!/bin/sh
# Copyright 2019, The Tor Project, Inc.
# See LICENSE for licensing information

# Integration test script for verifying that Tor configurations are parsed as
# we expect.
#
# Valid configurations are tested with --dump-config, which parses and
# validates the configuration before writing it out.  We then make sure that
# the result is what we expect, before parsing and dumping it again to make
# sure that there is no change.
#
# Invalid configurations are tested with --verify-config, which parses
# and validates the configuration. We capture its output and make sure that
# it contains the error message we expect.

# This script looks for its test cases as individual directories in
# src/test/conf_examples/.  Each test may have these files:
#
# torrc -- Usually needed. This file is passed to Tor on the command line
#      with the "-f" flag. (If you omit it, you'll test Tor's behavior when
#      it receives a nonexistent configuration file.)
#
# torrc.defaults -- Optional. If present, it is passed to Tor on the command
#      line with the --defaults-torrc option. If this file is absent, an empty
#      file is passed instead to prevent Tor from reading the system defaults.
#
# cmdline -- Optional. If present, it contains command-line arguments that
#      will be passed to Tor.
#
# expected -- If this file is present, then it should be the expected result
#      of "--dump-config short" for this test case.  Exactly one of
#      "expected" or "error" must be present, or the test will fail.
#
# error -- If this file is present, then it contains a regex that must be
#      matched by some line in the output of "--verify-config", which must
#      fail. Exactly one of "expected" or "error" must be present, or the
#      test will fail.

umask 077
set -e
die() { echo "$1" >&2 ; exit 5; }

# find the tor binary
if [ $# -ge 1 ]; then
  TOR_BINARY="${1}"
  shift
else
  TOR_BINARY="${TESTING_TOR_BINARY:-./src/app/tor}"
fi

# make a safe space for temporary files
DATA_DIR=$(mktemp -d -t tor_parseconf_tests.XXXXXX)
trap 'rm -rf "$DATA_DIR"' 0
touch "${DATA_DIR}/EMPTY" || die "Couldn't create empty file."

# This is where we look for examples
EXAMPLEDIR="$(dirname "$0")"/conf_examples

case "$(uname -s)" in
    CYGWIN*) WINDOWS=1;;
    MINGW*) WINDOWS=1;;
    MSYS*) WINDOWS=1;;
    *) WINDOWS=0;;
esac

# on Windows, we need to use diff -b because of line-ending issues; otherwise,
# we should use diff so that we detect whitespace changes.
diffcmd() {
    if test "$WINDOWS" = 1; then
        diff -b "$@"
    else
        diff "$@"
    fi
}

for dir in "${EXAMPLEDIR}"/*; do
    testname="$(basename "${dir}")"
    # We use printf since "echo -n" is not standard
    printf "%s: " "$testname"

    if test -f "${dir}/torrc.defaults"; then
        DEFAULTS="${dir}/torrc.defaults"
    else
        DEFAULTS="${DATA_DIR}/EMPTY"
    fi

    if test -f "${dir}/cmdline"; then
        CMDLINE="$(cat "${dir}"/cmdline)"
    else
        CMDLINE=""
    fi

    if test -f "${dir}/expected"; then
        if test -f "${dir}/error"; then
            echo "FAIL: Found both ${dir}/expected and ${dir}/error."
            echo "(Only one of these files should exist.)"
            exit 1
        fi

        # This case should succeed: run dump-config and see if it does.

        "${TOR_BINARY}" -f "${dir}"/torrc \
                        --defaults-torrc "${DEFAULTS}" \
                        --dump-config short \
                        ${CMDLINE} \
                        > "${DATA_DIR}/output.${testname}" \
                        || die "Failure: Tor exited."

        if diffcmd "${dir}/expected" "${DATA_DIR}/output.${testname}">/dev/null ; then
            # Check round-trip.
            "${TOR_BINARY}" -f "${DATA_DIR}/output.${testname}" \
                            --defaults-torrc "${DATA_DIR}/empty" \
                            --dump-config short \
                            > "${DATA_DIR}/output_2.${testname}" \
                        || die "Failure: Tor exited on round-trip."

            if ! cmp "${DATA_DIR}/output.${testname}" \
                 "${DATA_DIR}/output_2.${testname}"; then
                echo "Failure: did not match on round-trip."
                exit 1
            fi

            echo "OK"
        else
            echo "FAIL"
            diffcmd -u "${dir}/expected" "${DATA_DIR}/output.${testname}"
            exit 1
        fi

    elif test -f "${dir}/error"; then
        # This case should fail: run verify-config and see if it does.

        "${TOR_BINARY}" --verify-config \
                        -f "${dir}"/torrc \
                        --defaults-torrc "${DEFAULTS}" \
                        ${CMDLINE} \
                        > "${DATA_DIR}/output.${testname}" \
                        && die "Failure: Tor did not report an error."

        expect_err="$(cat "${dir}"/error)"
        if grep "${expect_err}" "${DATA_DIR}/output.${testname}" >/dev/null; then
            echo "OK"
        else
            echo "FAIL"
            echo "Expected error: ${expect_err}"
            echo "Tor said:"
            cat "${DATA_DIR}/output.${testname}"
            exit 1
        fi

    else
        # This case is not actually configured with a success or a failure.
        # call that an error.

        echo "FAIL: Did not find ${dir}/expected or ${dir}/error."
        exit 1
    fi

done
