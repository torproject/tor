#!/bin/sh
# Copyright 2004-2005 Nick Mathewson. 
# Copyright 2005-2007 Andrew Lewman
# Copyright 2008 The Tor Project, Inc.
# See LICENSE in Tor distribution for licensing information.

# This script builds a Macintosh OS X metapackage containing 2 packages:
#    - One for Tor.
#    - One for Startup script for Tor.
#
# This script expects to be run from the toplevel makefile, with VERSION
# set to the latest Tor version, and Tor already built.
#

# Read the documentation located in tor/doc/tor-osx-dmg-creation.txt on
# how to build Tor for OSX

###
# Helpful info on OS X packaging:
#   http://developer.apple.com/documentation/DeveloperTools/Conceptual/SoftwareDistribution/index.html
#   man packagemaker

# Make sure VERSION is set, so we don't name the package
# "Tor--$ARCH-Bundle.dmg"
if [ "XX$VERSION" = 'XX' ]; then
  echo "VERSION not set."
  exit 1
fi

## Determine OSX Version
# map version to name
if [ -x /usr/bin/sw_vers ]; then
# This is poor, yet functional.  We don't care about the 3rd number in
# the OS version
  OSVER=`/usr/bin/sw_vers | grep ProductVersion | cut -f2 | cut -d"." -f1,2`
    case "$OSVER" in
    "10.6") ARCH="i386";;
    "10.5") ARCH="i386";;
	"10.4") ARCH="i386";;
	"10.3") ARCH="ppc";;
	"10.2") ARCH="ppc";;
	"10.1") ARCH="ppc";;
	"10.0") ARCH="ppc";;
	*) ARCH="unknown";;
    esac
else
  ARCH="unknown"
fi

# Where will we put our temporary files?
BUILD_DIR=/tmp/tor-osx-$$
# Path to PackageMaker app.
PACKAGEMAKER=/Developer/Applications/Utilities/PackageMaker.app/Contents/MacOS/PackageMaker

umask 022

echo I might ask you for your password now, so you can sudo.

sudo rm -rf $BUILD_DIR
mkdir $BUILD_DIR || exit 1
for subdir in tor_packageroot tor_resources \
              torstartup_packageroot \
              torbundle_resources \
              output; do
    mkdir $BUILD_DIR/$subdir
done

### Make Tor package.

make install DESTDIR=$BUILD_DIR/tor_packageroot
cp contrib/osx/ReadMe.rtf $BUILD_DIR/tor_resources
chmod 755 contrib/osx/TorPostflight
cp contrib/osx/TorPostflight $BUILD_DIR/tor_resources/postflight
cp contrib/osx/addsysuser $BUILD_DIR/tor_resources/addsysuser
cp contrib/osx/Tor_Uninstaller.applescript $BUILD_DIR/tor_resources/Tor_Uninstaller.applescript
cp contrib/osx/uninstall_tor_bundle.sh $BUILD_DIR/tor_resources/uninstall_tor_bundle.sh
cp contrib/osx/package_list.txt $BUILD_DIR/tor_resources/package_list.txt
cp contrib/osx/tor_logo.gif $BUILD_DIR/tor_resources/background.gif
cp src/config/geoip $BUILD_DIR/tor_resources/geoip
cat <<EOF > $BUILD_DIR/tor_resources/Welcome.txt
Tor: an anonymous Internet communication system

Tor is a system for using the internet anonymously, and allowing
others to do so.
EOF

### Assemble documentation

DOC=$BUILD_DIR/tor_resources/documents
mkdir $DOC
mkdir $DOC/howto
groff doc/tor.1.in -T ps -m man | pstopdf -i -o $DOC/tor-reference.pdf
groff doc/tor-resolve.1 -T ps -m man | pstopdf -i -o $DOC/tor-resolve.pdf
mkdir $DOC/Advanced
cp doc/spec/*.txt $DOC/Advanced
cp doc/HACKING $DOC/Advanced/HACKING.txt
cp ChangeLog $DOC/Advanced/ChangeLog.txt

find $BUILD_DIR/tor_packageroot -print0 |sudo xargs -0 chown root:wheel

$PACKAGEMAKER -build              \
    -p $BUILD_DIR/output/Tor.pkg  \
    -f $BUILD_DIR/tor_packageroot \
    -r $BUILD_DIR/tor_resources   \
    -i contrib/osx/TorInfo.plist  \
    -d contrib/osx/TorDesc.plist

### Make Startup Script package

mkdir -p $BUILD_DIR/torstartup_packageroot/Library/StartupItems/Tor
cp contrib/osx/Tor contrib/osx/StartupParameters.plist \
   $BUILD_DIR/torstartup_packageroot/Library/StartupItems/Tor

find $BUILD_DIR/torstartup_packageroot -print0 | sudo xargs -0 chown root:wheel

$PACKAGEMAKER -build 		       \
  -p $BUILD_DIR/output/torstartup.pkg  \
  -f $BUILD_DIR/torstartup_packageroot \
  -i contrib/osx/TorStartupInfo.plist  \
  -d contrib/osx/TorStartupDesc.plist

### Assemble the metapackage.  Packagemaker won't buld metapackages from
# the command line, so we need to do it by hand.

MPKG=$BUILD_DIR/output/Tor-$VERSION-$ARCH-Bundle.mpkg
mkdir -p "$MPKG/Contents/Resources"
echo -n "pmkrpkg1" > "$MPKG/Contents/PkgInfo"
cp contrib/osx/ReadMe.rtf "$MPKG/Contents/Resources"
cp contrib/osx/TorBundleInfo.plist "$MPKG/Contents/Info.plist"
cp contrib/osx/TorBundleWelcome.rtf "$MPKG/Contents/Resources/Welcome.rtf"
cp contrib/osx/TorBundleDesc.plist "$MPKG/Contents/Resources/Description.plist"
cp contrib/osx/tor_logo.gif "$MPKG/Contents/Resources/background.gif"

# Move all the subpackages into place.  
mkdir $BUILD_DIR/output/.contained_packages
mv $BUILD_DIR/output/*.pkg $BUILD_DIR/OUTPUT/.contained_packages
( cd $BUILD_DIR/output/.contained_packages )

### Copy readmes and licenses into toplevel.
cp contrib/osx/ReadMe.rtf $BUILD_DIR/output/Tor\ ReadMe.rtf
cp LICENSE $BUILD_DIR/output/Tor\ License.txt

### Package it all into a DMG

find $BUILD_DIR/output -print0 | sudo xargs -0 chown root:wheel

sudo mv $BUILD_DIR/output "$BUILD_DIR/Tor-$VERSION-$ARCH-Bundle"
rm -f "Tor-$VERSION-$ARCH-Bundle.dmg"
USER="`whoami`"
sudo hdiutil create -format UDZO -imagekey zlib-level=9 -srcfolder "$BUILD_DIR/Tor-$VERSION-$ARCH-Bundle" "Tor-$VERSION-$ARCH-Bundle.dmg"
sudo chown "$USER" "Tor-$VERSION-$ARCH-Bundle.dmg"

sudo rm -rf $BUILD_DIR
