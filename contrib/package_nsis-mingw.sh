#!/bin/sh
#
# Script to package a Tor installer on win32.  This script assumes that
# you have already built Tor, that you are running msys/mingw, and that
# you know what you are doing.

# Start in the tor source directory after you've compiled tor.exe
# This means start as ./contrib/package_nsis-mingw.sh

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

cp src/or/tor.exe win_tmp/bin/
cp src/tools/tor-resolve.exe win_tmp/bin/
cp /usr/local/ssl/lib/libcrypto.a win_tmp/bin/
cp /usr/local/ssl/lib/libssl.a win_tmp/bin/
cp contrib/tor.ico win_tmp/bin/

# YOU must copy torbutton xpi into the contrib dir
#cp contrib/torbutton-1.0.4-fx+tb.xpi win_tmp/bin/

# There is no man2html in mingw.  
# Maybe we should add this into make dist instead.
# One has to do this manually and cp it do the tor-source/doc dir
#man2html doc/tor.1.in > win_tmp/tmp/tor-reference.html
#man2html doc/tor-resolve.1 > win_tmp/tmp/tor-resolve.html


clean_newlines() {
    perl -pe 's/^\n$/\r\n/mg; s/([^\r])\n$/\1\r\n/mg;' $1 >$2
}

clean_localstatedir() {
    perl -pe 's/^\n$/\r\n/mg; s/([^\r])\n$/\1\r\n/mg; s{\@LOCALSTATEDIR\@/(lib|log)/tor/}{C:\\Documents and Settings\\Application Data\\Tor\\}' $1 >$2
}

for fn in socks-extensions.txt dir-spec.txt tor-spec.txt HACKING rend-spec.txt control-spec.txt tor-doc.html tor-doc.css version-spec.txt; do
    clean_newlines doc/$fn win_tmp/doc/$fn
done

cp doc/design-paper/tor-design.pdf win_tmp/doc/design-paper/tor-design.pdf

for fn in tor-reference.html tor-resolve.html; do 
    clean_newlines doc/$fn win_tmp/doc/$fn
done

for fn in README AUTHORS ChangeLog LICENSE; do 
    clean_newlines $fn win_tmp/$fn
done

clean_localstatedir src/config/torrc.sample.in win_tmp/src/config/torrc.sample

cp contrib/tor-mingw.nsi win_tmp/contrib/

cd win_tmp
"C:\Program Files\NSIS\makensis.exe" contrib/tor-mingw.nsi
