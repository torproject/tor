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

if test $# -ge 1 ; then
  "$try_parse" "$@"
  exitcode=$?
else
  cd "$top" || exit 1
  # This is the layout in 0.3.5
  # Keep these lists consistent:
  #   - OWNED_TOR_C_FILES in Makefile.am
  #   - CHECK_FILES in pre-commit.git-hook and pre-push.git-hook
  #   - try_parse in check_cocci_parse.sh
  "$try_parse" \
    src/lib/*/*.[ch] \
    src/core/*/*.[ch] \
    src/feature/*/*.[ch] \
    src/app/*/*.[ch] \
    src/test/*.[ch] \
    src/test/*/*.[ch] \
    src/tools/*.[ch] \
    src/win32/*.[ch]
  exitcode=$?
fi

if test "$exitcode" != 0 ; then
    echo "Please fix these cocci parsing errors in the above files"
    echo "Set VERBOSE=1 for more details"
    echo "Try running test-operator-cleanup or 'make autostyle-operators'"
    echo "As a last resort, you can modify scripts/coccinelle/exceptions.txt"
fi

exit "$exitcode"
