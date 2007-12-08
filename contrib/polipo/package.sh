#!/bin/sh
# $Id: package.sh 8992 2006-12-23 03:12:09Z phobos $
# Copyright 2004-2005 Nick Mathewson & Andrew Lewman. 
# Copyright 2005-2007 Andrew Lewman
# See LICENSE in Polipo distribution for licensing information.

###
# Helpful info on OS X packaging:
#   http://developer.apple.com/documentation/DeveloperTools/Conceptual/SoftwareDistribution/index.html
#   man packagemaker

VERSION="1.0.3"

## Determine OSX Version
# map version to name
if [ -x /usr/bin/sw_vers ]; then
# This is poor, yet functional.  We don't care about the 3rd number in
# the OS version
  OSVER=`/usr/bin/sw_vers | grep ProductVersion | cut -f2 | cut -d"." -f1,2`
    case "$OSVER" in
    "10.5") OS="leopard" ARCH="universal";;
	"10.4") OS="tiger" ARCH="universal";;
	"10.3") OS="panther" ARCH="ppc";;
	"10.2") OS="jaguar" ARCH="ppc";;
	"10.1") OS="puma" ARCH="ppc";;
	"10.0") OS="cheetah" ARCH="ppc";;
	*) OS="unknown";;
    esac
else
  OS="unknown"
fi

# Where will we put our temporary files?
BUILD_DIR=/tmp/polipo-osx-$$
# Path to PackageMaker app.
PACKAGEMAKER=/Developer/Applications/Utilities/PackageMaker.app/Contents/MacOS/PackageMaker

umask 022

echo I might ask you for your password now, so you can sudo.

sudo rm -rf $BUILD_DIR
mkdir $BUILD_DIR || exit 1
for subdir in polipo_packageroot output; do
    mkdir $BUILD_DIR/$subdir
done

### Make Polipo package.
chmod 755 contrib/PolipoPostflight
mkdir -p $BUILD_DIR/polipo_packageroot/Library/Polipo/
cp polipo $BUILD_DIR/polipo_packageroot/polipo
cp config.sample $BUILD_DIR/polipo_packageroot/config
cp contrib/PolipoPostflight $BUILD_DIR/polipo_packageroot/postflight
cp contrib/addsysuser $BUILD_DIR/polipo_packageroot/addsysuser
cp contrib/uninstall_polipo_bundle.sh $BUILD_DIR/polipo_packageroot/uninstall_polipo_bundle.sh
cp localindex.html $BUILD_DIR/polipo_packageroot/index.html
cat <<EOF > $BUILD_DIR/polipo_packageroot/Welcome.txt
Polipo: a caching web proxy

Polipo is a small and fast caching web proxy (a web cache, an HTTP
proxy, a proxy server).
EOF

### Assemble documentation

groff polipo.man -T ps -m man | pstopdf -i -o $BUILD_DIR/polipo_packageroot/polipo.pdf
texi2html polipo.texi && cp polipo.html $BUILD_DIR/polipo_packageroot/polipo.html

find $BUILD_DIR/polipo_packageroot -print0 |sudo xargs -0 chown root:wheel

$PACKAGEMAKER -build              \
    -p $BUILD_DIR/output/Polipo.pkg  \
    -f $BUILD_DIR/polipo_packageroot \
    -i contrib/PolipoInfo.plist  \
    -d contrib/PolipoDesc.plist

### Package it all into a DMG

find $BUILD_DIR/output -print0 | sudo xargs -0 chown root:wheel

mv $BUILD_DIR/output "$BUILD_DIR/Polipo-$VERSION-$OS-$ARCH"
rm -f "Polipo-$VERSION-$OS-$ARCH-Bundle.dmg"
USER="`whoami`"
sudo hdiutil create -format UDZO -srcfolder "$BUILD_DIR/Polipo-$VERSION-$OS-$ARCH" "Polipo-$VERSION-$OS-$ARCH.dmg"
sudo chown "$USER" "Polipo-$VERSION-$OS-$ARCH.dmg"

#sudo rm -rf $BUILD_DIR
