#!/bin/sh

set -x

UNAME_OS=$(uname -s | cut -d_ -f1)
if test "$UNAME_OS" = 'CYGWIN' || \
   test "$UNAME_OS" = 'MSYS' || \
   test "$UNAME_OS" = 'MINGW'; then
  if test "$APPVEYOR" = 'True'; then
    echo "This test is disabled on Windows CI, as it requires firewall exemptions. Skipping." >&2
    exit 77
  fi
fi

exitcode=0

"${PYTHON:-python}" "${abs_top_srcdir:-.}/src/test/test_resolve.py" \
"${top_builddir:-.}/src/tools/tor-resolve" || exitcode=1

exit ${exitcode}
