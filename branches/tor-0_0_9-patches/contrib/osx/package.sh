#!/bin/sh

# Helpful info:
#   http://developer.apple.com/documentation/DeveloperTools/Conceptual/SoftwareDistribution/index.html
#   man packagemaker

if [ "XX$VERSION" = 'XX' ]; then
  echo "VERSION not set."
  exit 1
fi

PREFIX=/usr/local
BUILD_DIR=/tmp/tor-osx-$$
PRIVOXY_PKG_ZIP=~/src/privoxy-setup/privoxyosx_setup_3.0.3.zip
PACKAGEMAKER=/Developer/Applications/Utilities/PackageMaker.app/Contents/MacOS/PackageMaker

umask 022

rm -rf $BUILD_DIR
mkdir $BUILD_DIR || exit 1
for subdir in tor_packageroot tor_resources \
              torstartup_packageroot \
              privoxyconf_packageroot \
              torbundle_resources \
              output; do
    mkdir $BUILD_DIR/$subdir
done

make install DESTDIR=$BUILD_DIR/tor_packageroot
cp contrib/osx/ReadMe.rtf $BUILD_DIR/tor_resources
cp contrib/osx/License.rtf $BUILD_DIR/tor_resources
cat <<EOF > $BUILD_DIR/tor_resources/Welcome.txt
Tor: an anonymous Internet communication system

Tor is a system for using the internet anonymously, and allowing
others to do so.
EOF

$PACKAGEMAKER -build              \
    -p $BUILD_DIR/output/Tor.pkg  \
    -f $BUILD_DIR/tor_packageroot \
    -r $BUILD_DIR/tor_resources   \
    -i contrib/osx/TorInfo.plist  \
    -d contrib/osx/TorDesc.plist

mkdir -p $BUILD_DIR/privoxyconf_packageroot/Library/Privoxy
cp contrib/osx/privoxy.config $BUILD_DIR/privoxyconf_packageroot/Library/Privoxy/config

$PACKAGEMAKER -build                      \
    -p $BUILD_DIR/output/privoxyconf.pkg  \
    -f $BUILD_DIR/privoxyconf_packageroot \
    -i contrib/osx/PrivoxyConfInfo.plist \
    -i contrib/osx/PrivoxyConfDesc.plist

mkdir -p $BUILD_DIR/torstartup_packageroot/System/Library/StartupItems/Tor
cp contrib/osx/Tor contrib/osx/StartupParameters.plist \
   $BUILD_DIR/torstartup_packageroot/System/Library/StartupItems/Tor

$PACKAGEMAKER -build                    \
    -p $BUILD_DIR/output/torstartup.pkg \
    -f $BUILD_DIR/torstartup_packageroot \
    -i contrib/osx/TorStartupInfo.plist \
    -i contrib/osx/TorStartupDesc.plist


## Ug! Packagemaker won't buld metapackages.

MPKG=$BUILD_DIR/output/Tor\ Bundle.mpkg
mkdir -p "$MPKG/Contents/Resources"
echo -n "pmkrpkg1" > "$MPKG/Contents/PkgInfo"
cp contrib/osx/ReadMe.rtf "$MPKG/Contents/Resources"
cp contrib/osx/License.rtf "$MPKG/Contents/Resources"
cp contrib/osx/TorBundleInfo.plist "$MPKG/Contents/Info.plist"
cp contrib/osx/TorBundleWelcome.rtf "$MPKG/Contents/Resources/Welcome.rtf"
cp contrib/osx/TorBundleDesc.plist "$MPKG/Contents/Resources/Description.plist"

mkdir $BUILD_DIR/output/.contained_packages
mv $BUILD_DIR/output/*.pkg $BUILD_DIR/OUTPUT/.contained_packages
( cd $BUILD_DIR/output/.contained_packages && unzip $PRIVOXY_PKG_ZIP && find Privoxy.pkg -type d | xargs chmod u+w )

PRIVOXY_RESDIR=$BUILD_DIR/output/.contained_packages/Privoxy.pkg/Contents/Resources
cp $PRIVOXY_RESDIR/License.html $BUILD_DIR/output/Privoxy\ License.html
cp $PRIVOXY_RESDIR/ReadMe.txt $BUILD_DIR/output/Privoxy\ ReadMe.txt
cp contrib/osx/ReadMe.rtf $BUILD_DIR/output/Tor\ ReadMe.rtf
cp contrib/osx/License.rtf $BUILD_DIR/output/Tor\ License.rtf

DOC=$BUILD_DIR/output/Documents
mkdir $DOC
cp doc/tor-doc.html doc/tor-doc.css $DOC
cp AUTHORS $DOC/AUTHORS.txt
groff doc/tor.1 -T ps -m man | ps2pdf - $DOC/tor-reference.pdf
groff doc/tor-resolve.1 -T ps -m man | ps2pdf - $DOC/tor-resolve.pdf

mkdir $DOC/Advanced
cp doc/tor-spec.txt doc/rend-spec.txt doc/control-spec.txt doc/socks-extensions.txt $DOC/Advanced
cp doc/CLIENTS $DOC/Advanced/CLIENTS.txt
cp doc/HACKING $DOC/Advanced/HACKING.txt
cp ChangeLog $DOC/Advanced/ChangeLog.txt

mv $BUILD_DIR/output "$BUILD_DIR/Tor $VERSION Bundle"
rm -f "Tor $VERSION Bundle.dmg"
hdiutil create -format UDZO -srcfolder "$BUILD_DIR/Tor $VERSION Bundle" "Tor $VERSION Bundle.dmg"

rm -rf $BUILD_DIR
