#!/bin/sh

set -e

if [ ! -d "$1" ] ; then
    echo "I need a directory"
    exit 1
fi

which=$(basename "$1")

mkdir "$1.out"
afl-cmin -i "$1" -o "$1.out" -m none "./src/test/fuzz/fuzz-${which}"

