#!/bin/sh

if [ -x "`which autoreconf 2>/dev/null`" ] ; then
  exec autoreconf -ivf
fi

set -e

# Run this to generate all the initial makefiles, etc.
aclocal && \
	autoheader && \
	autoconf && \
	automake --add-missing --copy
