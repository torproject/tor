#!/bin/sh

# If we have coccinelle installed, run try_parse.sh on every filename passed
# as an argument. Uses the default coccinelle exceptions file, if
# $TOR_COCCI_EXCEPTIONS_FILE is not set.
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

"$try_parse" "$@"
exitcode=$?

if test "$exitcode" != 0 ; then
    echo "Please fix these cocci parsing errors in the above files"
    echo "Set VERBOSE=1 for more details"
    echo "Try running test-operator-cleanup or 'make autostyle-operators'"
    echo "As a last resort, you can modify scripts/coccinelle/exceptions.txt"
fi

exit "$exitcode"
