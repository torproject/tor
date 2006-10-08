#!/bin/sh
# Run this to generate all the initial makefiles, etc.
aclocal && \
	autoheader && \
	autoconf && \
	automake --add-missing --copy && \
	if test x$NOCONF = x ; then ./configure; fi
