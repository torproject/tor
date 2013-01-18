#!/bin/sh

if [ -x "`which autoreconf 2>/dev/null`" ] ; then
  opt="-if"

  for i in $@; do
    case "$i" in
      -v)
        opt=$opt"v"
        ;;
    esac
  done

  exec autoreconf $opt
fi

set -e

# Run this to generate all the initial makefiles, etc.
aclocal && \
	autoheader && \
	autoconf && \
	automake --add-missing --copy
