#!/bin/sh

# Copyright (c) The Tor Project, Inc.
# See LICENSE for licensing information
# Run this to generate .html.in or .1.in files from asciidoc files.
# Arguments:
# html|man asciidocpath outputfile

set -e

if [ $# != 3 ]; then
  exit 1;
fi

output=$3

if [ "$1" = "html" ]; then
    input=${output%%.html.in}.1.txt
    base=${output%%.html.in}
    if [ "$2" != none ]; then
      "$2" -d manpage -o $output $input;
    else
      echo "==================================";
      echo;
      echo "You need asciidoc installed to be able to build the manpage.";
      echo "To build without manpages, use the --disable-asciidoc argument";
      echo "when calling configure.";
      echo;
      echo "==================================";
      exit 1;
    fi
elif [ "$1" = "man" ]; then
    input=${output%%.1.in}.1.txt
    base=${output%%.1.in}
    
    if test "$2" = none; then
      echo "==================================";
      echo;
      echo "You need asciidoc installed to be able to build the manpage.";
      echo "To build without manpages, use the --disable-asciidoc argument";
      echo "when calling configure.";
      echo;
      echo "==================================";
      exit 1;
    fi
    if "$2" -f manpage $input; then
      mv $base.1 $output;
    else
      echo "==================================";
      echo;
      echo "a2x is installed, but some required docbook support files are";
      echo "missing. Please install docbook-xsl, docbook-xml, and";
      echo "libxml2-utils (Debian) or similar.";
      echo;
      echo "==================================";
      exit 1;
    fi
fi

