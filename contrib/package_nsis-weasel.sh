#!/bin/sh

set -e

#
# Script to package a Tor installer on win32.  This script assumes that
# you have already built Tor, that you are running cygwin, and that your
# environment is basically exactly the same as Nick's.

if ! [ -d Win32Build ] || ! [ -d contrib ]; then
	echo "No Win32Build and/or no contrib directory here.  Are we in the right place?" >&2
	exit 1
fi

rm -rf win_tmp
mkdir win_tmp
mkdir win_tmp/bin
mkdir win_tmp/contrib
mkdir win_tmp/doc
mkdir win_tmp/doc/design-paper
mkdir win_tmp/doc/contrib
mkdir win_tmp/src
mkdir win_tmp/src/config
mkdir win_tmp/tmp

cp Win32Build/vc7/Tor/Debug/Tor.exe win_tmp/bin/tor.exe
cp Win32Build/vc7/tor_resolve/Debug/tor_resolve.exe win_tmp/bin
cp ../c-windows-system32/libeay32.dll win_tmp/bin
cp ../c-windows-system32/ssleay32.dll win_tmp/bin

man2html doc/tor.1.in > win_tmp/tmp/tor-reference.html
man2html doc/tor-resolve.1 > win_tmp/tmp/tor-resolve.html

clean_newlines() {
    perl -pe 's/^\n$/\r\n/mg; s/([^\r])\n$/\1\r\n/mg;' $1 >$2
}

clean_localstatedir() {
    perl -pe 's/^\n$/\r\n/mg; s/([^\r])\n$/\1\r\n/mg; s{\@LOCALSTATEDIR\@/(lib|log)/tor/}{C:\\Documents and Settings\\Application Data\\Tor\\}' $1 >$2
}

for fn in \
	HACKING \
	control-spec.txt \
	dir-spec.txt \
	rend-spec.txt \
	socks-extensions.txt \
	stylesheet.css \
	tor-spec.txt \
	tor-doc-osx.html \
	tor-doc-server.html \
	tor-doc-unix.html \
	tor-doc-win32.html \
	tor-hidden-service.html \
	tor-switchproxy.html \
	version-spec.txt \
	; do
    clean_newlines doc/$fn win_tmp/doc/$fn
done

cp doc/design-paper/tor-design.pdf win_tmp/doc/design-paper/tor-design.pdf

for fn in tor-reference.html tor-resolve.html; do \
    clean_newlines win_tmp/tmp/$fn win_tmp/doc/$fn
done

for fn in README AUTHORS ChangeLog LICENSE; do \
    clean_newlines $fn win_tmp/$fn
done

clean_localstatedir src/config/torrc.sample.in win_tmp/src/config/torrc.sample

cp contrib/tor.nsi win_tmp/contrib

cd win_tmp/contrib

echo "Now run"
echo '  t:'
echo '  cd \tor\win_tmp\contrib'
echo '  c:\programme\nsis\makensis tor.nsi'
echo '  move tor-*.exe ../..'
