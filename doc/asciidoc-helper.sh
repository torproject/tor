#!/bin/sh

# Copyright (c) The Tor Project, Inc.
# See LICENSE for licensing information
# Run this to generate .html.in or .1.in files from asciidoc files.
# Arguments:
# html|man asciidocpath sedpath outputfile

set -e

if [ $# != 4 ]; then
  exit 1;
fi

output=$4
input=`echo $output | $3 -e 's/html\.in$/1\.txt/g' -e 's/1\.in$/1\.txt/g'`
base=`echo $output | $3 -e 's/\.html\.in$//g' -e 's/\.1\.in$//g'`

if [ "$1" = "html" ]; then
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
