#!/bin/sh
# Copyright 2019, The Tor Project, Inc.
# See LICENSE for licensing information

# Integration test script for verifying that Tor configurations are parsed as
# we expect.
#
# Valid configurations are tested with --dump-config, which parses and
# validates the configuration before writing it out.  We then make sure that
# the result is what we expect, before parsing and dumping it again to make
# sure that there is no change. Optionally, we can also test the log messages
# with --verify-config.
#
# Invalid configurations are tested with --verify-config, which parses
# and validates the configuration. We capture its output and make sure that
# it contains the error message we expect.
#
# When tor is compiled with different libraries or modules, some
# configurations may have different results. We can specify these result
# variants using additional result files.

# This script looks for its test cases as individual directories in
# src/test/conf_examples/.  Each test may have these files:
#
# Configuration Files
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
# (included torrc files or directories) -- Optional. Additional files can be
#      included in configuration, using the "%include" directive. Files or
#      directories can be included in any of the config files listed above.
#      Include paths should be specified relative to the test case directory.
#
# Result Files
#
# expected -- If this file is present, then it should be the expected result
#      of "--dump-config short" for this test case.  Exactly one of
#      "expected" or "error" must be present, or the test will fail.
#
# expected_log -- Optional. If this file is present, then it contains a regex
#      that must be matched by some line in the output of "--verify-config",
#      which must succeed. Only used if "expected" is also present.
#
# error -- If this file is present, then it contains a regex that must be
#      matched by some line in the output of "--verify-config", which must
#      fail. Exactly one of "expected" or "error" must be present, or the
#      test will fail.
#
# {expected,expected_log,error}_${TOR_LIBS_ENABLED}* -- If this file is
#      present, then the outcome is different when some optional libraries are
#      enabled. If there is no result file matching the exact list of enabled
#      libraries, the script searches for result files with one or more of
#      those libraries disabled. The search terminates at the standard result
#      file. If expected* is present, the script also searches for
#      expected_log*.
#
#      For example:
#      A test that succeeds, regardless of any enabled libraries:
#       - expected
#      A test that has a different result if the nss library is enabled
#      (but the same result if any other library is enabled). We also check
#      the log output in this test:
#       - expected
#       - expected_log
#       - expected_nss
#       - expected_log_nss
#      A test that fails if the lzma and zstd modules are *not* enabled:
#       - error
#       - expected_lzma_zstd
#
# {expected,expected_log,error}*_no_${TOR_MODULES_DISABLED} -- If this file is
#      present, then the outcome is different when some modules are disabled.
#      If there is no result file matching the exact list of disabled modules,
#      the standard result file is used. If expected* is present, the script
#      also searches for expected_log*.
#
#      For example:
#      A test that succeeds, regardless of any disabled modules:
#       - expected
#      A test that has a different result if the relay module is disabled
#      (but the same result if just the dirauth module is disabled):
#       - expected
#       - expected_no_relay_dirauth
#      A test that fails if the dirauth module is disabled:
#       - expected
#       - error_no_dirauth
#       - error_no_relay_dirauth
#      (Disabling the relay module also disables dirauth module. But we don't
#      want to encode that knowledge in this test script, so we supply a
#      separate result file for every combination of disabled modules that
#      has a different result.)

umask 077
set -e

MYNAME="$0"

# emulate realpath(), in case coreutils or equivalent is not installed.
abspath() {
    f="$*"
    if test -d "$f"; then
        dir="$f"
        base=""
    else
        dir="$(dirname "$f")"
        base="/$(basename "$f")"
    fi
    dir="$(cd "$dir" && pwd)"
    echo "$dir$base"
}

# find the tor binary
if test $# -ge 1; then
  TOR_BINARY="$1"
  shift
else
  TOR_BINARY="${TESTING_TOR_BINARY:-./src/app/tor}"
fi

TOR_BINARY="$(abspath "$TOR_BINARY")"

echo "TOR BINARY IS $TOR_BINARY"

# make a safe space for temporary files
DATA_DIR=$(mktemp -d -t tor_parseconf_tests.XXXXXX)
trap 'rm -rf "$DATA_DIR"' 0

# This is where we look for examples
EXAMPLEDIR="$(dirname "$0")"/conf_examples

case "$(uname -s)" in
    CYGWIN*) WINDOWS=1;;
    MINGW*) WINDOWS=1;;
    MSYS*) WINDOWS=1;;
    *) WINDOWS=0;;
esac

####
# BUG WORKAROUND FOR 31757:
#  On Appveyor, it seems that Tor sometimes randomly fails to produce
#  output with --dump-config.  Whil we are figuring this out, do not treat
#  windows errors as hard failures.
####
if test "$WINDOWS" = 1; then
    EXITCODE=0
else
    EXITCODE=1
fi

FINAL_EXIT=0

NEXT_TEST=
fail() { printf "FAIL: " >&2;
         # The first argument is a printf string, so this warning is spurious
         # shellcheck disable=SC2059
         printf "$@" >&2;
         printf "\\n" >&2;
         NEXT_TEST="yes"
         FINAL_EXIT=$EXITCODE; }
die()  { printf "FAIL: CRITICAL error in '%s':" "$MYNAME" >&2;
         # The first argument is a printf string, so this warning is spurious
         # shellcheck disable=SC2059
         printf "$@" >&2;
         printf "\\n" >&2;
         exit $EXITCODE; }

if test "$WINDOWS" = 1; then
    FILTER="dos2unix"
else
    FILTER="cat"
fi

EMPTY="${DATA_DIR}/EMPTY"

touch "$EMPTY" || die "Couldn't create empty file '%s'." \
                      "$EMPTY"

STANDARD_LIBS="libevent\\|openssl\\|zlib"
# Lib names are restricted to [a-z0-9]* at the moment
# We don't actually want to support foreign accents here
# shellcheck disable=SC2018,SC2019
TOR_LIBS_ENABLED="$("$TOR_BINARY" --verify-config \
                      -f "$EMPTY" --defaults-torrc "$EMPTY" \
                    | sed -n 's/.* Tor .* running on .* with\(.*\)\./\1/p' \
                    | tr 'A-Z' 'a-z' | tr ',' '\n' \
                    | grep -v "$STANDARD_LIBS" | grep -v "n/a" \
                    | sed 's/\( and\)* \(lib\)*\([a-z0-9]*\) .*/\3/' \
                    | sort | tr '\n' '_')"
# Remove the last underscore, if there is one
TOR_LIBS_ENABLED=${TOR_LIBS_ENABLED%_}

# If we ever have more than 3 optional libraries, we'll need more code here
TOR_LIBS_ENABLED_COUNT="$(echo "$TOR_LIBS_ENABLED_SEARCH" \
                          | tr ' ' '\n' | wc -l)"
if test "$TOR_LIBS_ENABLED_COUNT" -gt 3; then
    die "Can not handle more than 3 optional libraries"
fi
# Brute-force the combinations of libraries
TOR_LIBS_ENABLED_SEARCH_3="$(echo "$TOR_LIBS_ENABLED" \
    | sed -n \
      's/^\([^_]*\)_\([^_]*\)_\([^_]*\)$/_\1_\2 _\1_\3 _\2_\3 _\1 _\2 _\3/p')"
TOR_LIBS_ENABLED_SEARCH_2="$(echo "$TOR_LIBS_ENABLED" \
    | sed -n 's/^\([^_]*\)_\([^_]*\)$/_\1 _\2/p')"
TOR_LIBS_ENABLED_SEARCH="_$TOR_LIBS_ENABLED \
                           $TOR_LIBS_ENABLED_SEARCH_3 \
                           $TOR_LIBS_ENABLED_SEARCH_2"
TOR_LIBS_ENABLED_SEARCH="$(echo "$TOR_LIBS_ENABLED_SEARCH" | tr ' ' '\n' \
                           | grep -v '^_*$' | tr '\n' ' ')"

TOR_MODULES_DISABLED="$("$TOR_BINARY" --list-modules | grep ': no' \
                        | cut -d ':' -f1 | sort | tr '\n' '_')"
# Remove the last underscore, if there is one
TOR_MODULES_DISABLED=${TOR_MODULES_DISABLED%_}

echo "Tor is configured with:"
echo "Optional Libraries: ${TOR_LIBS_ENABLED:-(None)}"
if test "$TOR_LIBS_ENABLED"; then
    echo "Optional Library Search List: $TOR_LIBS_ENABLED_SEARCH"
fi
echo "Disabled Modules: ${TOR_MODULES_DISABLED:-(None)}"

for dir in "${EXAMPLEDIR}"/*; do
    NEXT_TEST=

    if ! test -d "$dir"; then
       # Only count directories.
       continue
    fi

    testname="$(basename "${dir}")"
    # We use printf since "echo -n" is not standard
    printf "%s: " \
           "$testname"

    PREV_DIR="$(pwd)"
    cd "$dir"

    if test -f "./torrc.defaults"; then
        DEFAULTS="./torrc.defaults"
    else
        DEFAULTS="${DATA_DIR}/EMPTY"
    fi

    if test -f "./cmdline"; then
        CMDLINE="$(cat ./cmdline)"
    else
        CMDLINE=""
    fi

    EXPECTED=
    EXPECTED_LOG=
    ERROR=
    # Search for a custom result file for any combination of enabled optional
    # libraries
    # The libs in the list are [A-Za-z0-9_]* and space-separated.
    # shellcheck disable=SC2086
    for lib_suffix in $TOR_LIBS_ENABLED_SEARCH ""; do
        # Search for a custom result file for any disabled modules
        for mod_suffix in "_no_${TOR_MODULES_DISABLED}" ""; do
            suffix="${lib_suffix}${mod_suffix}"

            if test -f "./expected${suffix}"; then

                # Check for broken configs
                if test -f "./error${suffix}"; then
                    fail "Found both '%s' and '%s'.%s" \
                         "${dir}/expected${suffix}" \
                         "${dir}/error${suffix}" \
                         "(Only one of these files should exist.)"
                    break
                fi

                EXPECTED="./expected${suffix}"
                if test -f "./expected_log${suffix}"; then
                    EXPECTED_LOG="./expected_log${suffix}"
                fi
                break

            elif test -f "./error${suffix}"; then
                ERROR="./error${suffix}"
                break
            fi
        done

        # Exit as soon as the inner loop finds a file, or fails
        if test -f "$EXPECTED" || test -f "$ERROR" || test "$NEXT_TEST"; then
            break
        fi
    done

    if test "$NEXT_TEST"; then
        # The test failed inside the file search loop: go to the next test
        continue
    elif test -f "$EXPECTED"; then
        # This case should succeed: run dump-config and see if it does.

        if test -f "$EXPECTED_LOG"; then
            if ! test -s "$EXPECTED_LOG"; then
                fail "Expected log file '%s' is empty.%s" \
                     "$EXPECTED_LOG" \
                     "(Empty expected log files match any output.)"
                continue
            fi
        fi

        "$TOR_BINARY" -f "./torrc" \
                      --defaults-torrc "$DEFAULTS" \
                      --dump-config short \
                      $CMDLINE > "${DATA_DIR}/output_raw.${testname}" \
            || fail "'%s': Tor --dump-config reported an error." \
                    "$EXPECTED"

        "$FILTER" "${DATA_DIR}/output_raw.${testname}" \
                  > "${DATA_DIR}/output.${testname}" \
            || fail "'%s': Filter '%s' reported an error." \
                    "$EXPECTED" \
                    "$FILTER"

        if cmp "$EXPECTED" "${DATA_DIR}/output.${testname}" > /dev/null; then
            # Check round-trip.
            "$TOR_BINARY" -f "${DATA_DIR}/output.${testname}" \
                          --defaults-torrc "$EMPTY" \
                          --dump-config short \
                          > "${DATA_DIR}/output_2_raw.${testname}" \
                || fail "'%s': Tor --dump-config reported an error%s." \
                        "$EXPECTED" \
                        " on round-trip"

            "$FILTER" "${DATA_DIR}/output_2_raw.${testname}" \
                      > "${DATA_DIR}/output_2.${testname}" \
                || fail "'%s': Filter '%s' reported an error." \
                        "$EXPECTED" \
                        "$FILTER"

            if ! cmp "${DATA_DIR}/output.${testname}" \
                 "${DATA_DIR}/output_2.${testname}"; then
                fail "'%s': did not match on round-trip:" \
                     "$EXPECTED"
                diff -u "${DATA_DIR}/output.${testname}" \
                     "${DATA_DIR}/output_2.${testname}" >&2 \
                    || true
            fi
        else
            if test "$(wc -c < "${DATA_DIR}/output.${testname}")" = 0; then
                # There was no output -- probably we failed.
                fail "'%s': Tor said:" \
                     "$EXPECTED"
                "$TOR_BINARY" -f "./torrc" \
                              --defaults-torrc "$DEFAULTS" \
                              --verify-config \
                              $CMDLINE >&2 \
                    || true
            fi
            fail "'%s' did not match:" \
                 "$EXPECTED"
            diff -u "$EXPECTED" "${DATA_DIR}/output.${testname}" >&2 \
                || true
        fi

        if test -f "$EXPECTED_LOG" || test "$NEXT_TEST"; then
            # This case should succeed: run verify-config and see if it does.
            #
            # As a temporary hack, we also use this code when --dump-config
            # has failed, to display the error logs.
            if ! test -f "$EXPECTED_LOG"; then
                NON_EMPTY="${DATA_DIR}/NON_EMPTY"
                echo "This pattern should not match any log messages" \
                     > "$NON_EMPTY"
                EXPECTED_LOG=$NON_EMPTY
            fi

            "$TOR_BINARY" --verify-config \
                          -f ./torrc \
                          --defaults-torrc "$DEFAULTS" \
                          $CMDLINE \
                          > "${DATA_DIR}/output_log.${testname}" \
                || fail "'%s': Tor --verify-config reported an error." \
                        "$EXPECTED_LOG"

            expect_log="$(cat "${EXPECTED_LOG}")"
            if grep "$expect_log" "${DATA_DIR}/output_log.${testname}" \
                    > /dev/null; then
                :
            else
                fail "Expected '%s':\\n%s\\nTor said:" \
                     "$EXPECTED_LOG" \
                     "$expect_log"
                cat "${DATA_DIR}/output_log.${testname}" >&2
            fi
        fi

        if test -z "$NEXT_TEST"; then
            echo "OK"
        fi

   elif test -f "$ERROR"; then
        # This case should fail: run verify-config and see if it does.

        if ! test -s "$ERROR"; then
            fail "Error file '%s' is empty.%s" \
                 "$ERROR" \
                 "(Empty error files match any output.)"
            continue
        fi

        "$TOR_BINARY" --verify-config \
                      -f ./torrc \
                      --defaults-torrc "$DEFAULTS" \
                      $CMDLINE \
                      > "${DATA_DIR}/output.${testname}" \
            && fail "'%s': Tor did not report an error." \
                    "$ERROR"

        expect_err="$(cat "${ERROR}")"
        if grep "$expect_err" "${DATA_DIR}/output.${testname}" > /dev/null; then
            echo "OK"
        else
            fail "Expected '%s':\\n%s\\nTor said:" \
                 "$ERROR" \
                 "$expect_err"
            cat "${DATA_DIR}/output.${testname}" >&2
        fi

    else
        # This case is not actually configured with a success or a failure.
        # call that an error.
        fail "Did not find ${dir}/*expected or ${dir}/*error."
    fi

    cd "$PREV_DIR"

done

exit $FINAL_EXIT
