#!/bin/sh

set -e

# Run this to generate all the initial makefiles, etc.
aclocal && \
	autoheader && \
	autoconf && \
	automake --add-missing --copy
