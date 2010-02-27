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
      echo "The manpage in html form for $base will ";
      echo "NOT be available, because asciidoc doesn't appear to be ";
      echo "installed!";
      echo;
      echo "==================================";
    fi
elif [ "$1" = "man" ]; then
    input=${output%%.1.in}.1.txt
    base=${output%%.1.in}
    
    if test "$2" != none; then
      if $2 -f manpage $input; then
        mv $base.1 $output;
      else
        echo "==================================";
        echo;
        echo "a2x is installed, but some required docbook support files are";
        echo "missing. Please install docbook-xsl and docbook-xml (Debian)";
        echo "or similar.";
        echo;
        echo "==================================";
      fi;
    else
      echo "==================================";
      echo;
      echo "The manpage for $base will NOT be ";
      echo "available, because a2x doesn't appear to be installed!";
      echo;
      echo "==================================";
    fi
fi

touch $output; \
