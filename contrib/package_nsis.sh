#!/bin/sh
#
# Script to package a Tor installer on win32.  This script assumes that
# you have already built Tor, that you are running cygwin, and that your
# environment is basically exactly the same as Nick's.

rm -rf win_tmp
mkdir win_tmp
mkdir win_tmp/bin
mkdir win_tmp/contrib
mkdir win_tmp/doc
mkdir win_tmp/doc/design-paper
mkdir win_tmp/doc/contrib
mkdir win_tmp/tmp
mkdir win_tmp/src
mkdir win_tmp/src/config

#cp Win32Build/vc6/tor/Debug/tor.exe win_tmp/bin
#cp Win32Build/vc6/tor_resolve/Debug/tor_resolve.exe win_tmp/bin
#cp c:/windows/system32/libeay32.dll win_tmp/bin
#cp c:/windows/system32/ssleay32.dll win_tmp/bin

man2html doc/tor.1.in > win_tmp/tmp/tor-reference.html
man2html doc/tor-resolve.1 > win_tmp/tmp/tor-resolve.html

clean_newlines() {
    perl -pe 'BEGIN {undef $;} s/^\n$/\r\n/mg; s/([^\r])\n$/\1\r\n/mg;' $1 >$2
}

for fn in CLIENTS tor-spec.txt HACKING rend-spec.txt control-spec.txt \
   tor-doc.html tor-doc.css; do
    clean_newlines doc/$fn win_tmp/doc/$fn
done

for fn in tor-reference.html tor-resolve.html; do \
    clean_newlines win_tmp/$fn win_tmp/doc/$fn
done

for fn in README AUTHORS ChangeLog; do \
    clean_newlines $fn win_tmp/$fn
done

clean_newlines src/config/torrc.sample.in win_tmp/src/config/torrc.sample

cp contrib/tor.nsi win_tmp/contrib

cd win_tmp/contrib
makensis tor.nsi
mv tor-*.exe ../..
