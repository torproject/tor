#!/bin/sh
# Run this to generate all the initial makefiles, etc.
aclocal && autoheader && autoconf && automake
./configure --enable-debug

