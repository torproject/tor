#!/bin/sh

# If we have coccinelle installed, run try_parse.sh on every filename passed
# as an argument. If no filenames are supplied, scan a standard Tor 0.3.5 or
# later directory layout.
#
# Uses the default coccinelle exceptions file, or $TOR_COCCI_EXCEPTIONS_FILE,
# if it is set.
#
# Use TOR_COCCI_EXCEPTIONS_FILE=/dev/null check_cocci_parse.sh to disable
# the default exception file.
#
# If spatch is not installed, remind the user to install it, but exit with
# a success error status.

scripts_cocci="$(dirname "$0")"
top="$scripts_cocci/../.."
try_parse="$scripts_cocci/try_parse.sh"

exitcode=0

export TOR_COCCI_EXCEPTIONS_FILE="${TOR_COCCI_EXCEPTIONS_FILE:-$scripts_cocci/exceptions.txt}"

if ! command -v spatch; then
    echo "Install coccinelle's spatch to check cocci C parsing!"
    exit "$exitcode"
fi

if test $# -gt 1 ; then
  "$try_parse" "$@"
  exitcode=$?
else
  # This is the layout in 0.3.5
  "$try_parse" \
    src/lib/*/*.[ch] \
    src/core/*/*.[ch] \
    src/feature/*/*.[ch] \
    src/app/*/*.[ch] \
    src/test/*.[ch] \
    src/test/*/*.[ch] \
    src/tools/*.[ch]
  exitcode=$?
fi

if test "$exitcode" != 0 ; then
    echo "Please fix these cocci parsing errors"
    echo "Try using test-operator-cleanup or 'make autostyle-operators'"
    echo "As a last resort, you can modify scripts/coccinelle/exceptions.txt"
fi

exit "$exitcode"
