#!/bin/sh

set -eu

if test "$1" = "" ; then
    echo "I need a package as an argument."
    exit 1
fi

PACKAGEFILE=$1

if test ! -f "$PACKAGEFILE" ; then
    echo "$PACKAGEFILE is not a file."
    exit 1
fi

DIGESTNAME=sha256
DIGESTOUTPUT=`gpg --print-md $DIGESTNAME $PACKAGEFILE`

RAWDIGEST=`gpg --print-md $DIGESTNAME $PACKAGEFILE | sed -e 's/^[^ ]*: //' `

# These regexes are a little fragile, but I think they work for us.
VERSION=`echo $PACKAGEFILE | sed -e 's/^[a-z\-]*//' -e 's/\.[\.a-z]*$//' `
PACKAGE=`echo $PACKAGEFILE | sed -e 's/-[0-9].*//'`
SIGFILE_UNSIGNED="$PACKAGE-$VERSION-signature"
SIGNATUREFILE="$SIGFILE_UNSIGNED.asc"

cat >$SIGFILE_UNSIGNED <<EOF
This is the signature file for "$PACKAGEFILE",
which contains version "$VERSION" of "$PACKAGE".

Here's how to check this signature.

1) Make sure that this is really a signature file, and not a forgery,
   with:

     "gpg --verify $SIGNATUREFILE"

   The key should be one of the keys that signs the Tor release; the
   official Tor website has more information on those.

   If this step fails, then either you are missing the correct key, or
   this signature file was not really signed by a Tor packager.
   Beware!

2) Make sure that the package you wanted is indeed "$PACKAGE", and that
   its version you wanted is indeed "$VERSION".  If you wanted a
   different package, or a different version, this signature file is
   not the right one!

3) Now that you're sure you have the right signature file, make sure
   that you got the right package.  Check its $DIGESTNAME digest with

     "gpg --print-md $DIGESTNAME $PACKAGEFILE"

   The output should match this, exactly:

$DIGESTOUTPUT

   Make sure that every part of the output matches: don't just check the
   first few characters.  If the digest does not match, you do not have
   the right package file.  It could even be a forgery.

Frequently asked questions:

Q: Why not just sign the package file, like you used to do?
A: GPG signatures authenticate file contents, but not file names.  If
   somebody gave you a renamed file with a matching renamed signature
   file, the signature would still be given as "valid".

-- 
FILENAME: $PACKAGEFILE
PACKAGE: $PACKAGE
VERSION: $VERSION
DIGESTALG: $DIGESTNAME
DIGEST: $RAWDIGEST
EOF

gpg --clearsign $SIGFILE_UNSIGNED
