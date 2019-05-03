#!/bin/sh

set -x

UNAME_OS=$(uname -s | cut -d_ -f1)
if test "$UNAME_OS" = 'CYGWIN' || \
   test "$UNAME_OS" = 'MSYS' || \
   test "$UNAME_OS" = 'MINGW' || \
   test "$UNAME_OS" = 'MINGW32' || \
   test "$UNAME_OS" = 'MINGW64'; then
  if test "$APPVEYOR" = 'True'; then
    echo "This test is disabled on Windows CI, as it requires firewall exemptions. Skipping." >&2
    exit 77
  fi
fi

exitcode=0

tmpdir=
clean () {
  if [ -n "$tmpdir" ] && [ -d "$tmpdir" ]; then
    rm -rf "$tmpdir"
  fi
}

trap clean EXIT HUP INT TERM

tmpdir="$(mktemp -d -t tor_include_test.XXXXXX)"
if [ -z "$tmpdir" ]; then
  echo >&2 mktemp failed
  exit 2
elif [ ! -d "$tmpdir" ]; then
  echo >&2 mktemp failed to make a directory
  exit 3
fi

datadir="$tmpdir/data"
mkdir "$datadir"

configdir="$tmpdir/config"
mkdir "$configdir"

# translate paths to windows format
if test "$UNAME_OS" = 'CYGWIN' || \
   test "$UNAME_OS" = 'MSYS' || \
   test "$UNAME_OS" = 'MINGW' || \
   test "$UNAME_OS" = 'MINGW32' || \
   test "$UNAME_OS" = 'MINGW64'; then
    datadir=`cygpath --windows "$datadir"`
    configdir=`cygpath --windows "$configdir"`
fi

# create test folder structure in configdir
torrcd="$configdir/torrc.d"
mkdir "$torrcd"
mkdir "$torrcd/folder"
echo "RecommendedVersions 1" > "$torrcd/01_one.conf"
echo "RecommendedVersions 2" > "$torrcd/02_two.conf"
echo "RecommendedVersions 3" > "$torrcd/aa_three.conf"
echo "RecommendedVersions 6" > "$torrcd/foo"
echo "RecommendedVersions 4" > "$torrcd/folder/04_four.conf"
echo "RecommendedVersions 5" > "$torrcd/folder/05_five.conf"
torrc="$configdir/torrc"
echo "Sandbox 1" > "$torrc"
echo "%include $torrcd/*.conf" >> "$torrc"
echo "%include $torrcd/f*" >> "$torrc"
echo "%include $torrcd/*/*" >> "$torrc"

"${PYTHON:-python}" "${abs_top_srcdir:-.}/src/test/test_include.py" "${TESTING_TOR_BINARY}" "$datadir" "$configdir" || exitcode=1

exit ${exitcode}
