#!/bin/sh

C_FILES=`echo src/common/*.c src/or/*.c src/tools/*.c`
CFLAGS="-Isrc/ext/trunnel -Isrc/trunnel -I. -Isrc/ext -Isrc/common -DLOCALSTATEDIR=\"\" -DSHARE_DATADIR=\"\" -Dinline="

mkdir -p callgraph/src/common
mkdir -p callgraph/src/or
mkdir -p callgraph/src/tools

for fn in $C_FILES; do
  echo $fn
  clang $CFLAGS  -S -emit-llvm -fno-inline -o - $fn  | \
    opt -analyze -print-callgraph >/dev/null 2> "callgraph/${fn}allgraph"
done
