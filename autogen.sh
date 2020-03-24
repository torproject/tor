#!/bin/sh

if command -v autoreconf; then
  opt="-i -f -W all,error"

  for i in "$@"; do
    case "$i" in
      -v)
        opt="${opt} -v"
        ;;
    esac
  done

  # shellcheck disable=SC2086
  exec autoreconf $opt
fi

set -e

# Run this to generate all the initial makefiles, etc.
aclocal -I m4 && \
	autoheader && \
	autoconf && \
	automake --add-missing --copy
