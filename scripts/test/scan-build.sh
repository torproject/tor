#!/bin/sh
# Copyright 2014 The Tor Project, Inc
# See LICENSE for licensing information
#
# This script is used for running a bunch of clang scan-build checkers
# on Tor.

CHECKERS="\
    -disable-checker deadcode.DeadStores \
    -enable-checker alpha.core.CastSize \
    -enable-checker alpha.core.CastToStruct \
    -enable-checker alpha.core.IdenticalExpr \
    -enable-checker alpha.core.SizeofPtr \
    -enable-checker alpha.security.ArrayBoundV2 \
    -enable-checker alpha.security.MallocOverflow \
    -enable-checker alpha.security.ReturnPtrRange \
    -enable-checker alpha.unix.SimpleStream
    -enable-checker alpha.unix.cstring.BufferOverlap \
    -enable-checker alpha.unix.cstring.NotNullTerminated \
    -enable-checker alpha.unix.cstring.OutOfBounds \
    -enable-checker alpha.core.FixedAddr \
    -enable-checker security.insecureAPI.strcpy \
    -enable-checker alpha.unix.PthreadLock \
    -enable-checker alpha.core.PointerArithm \
    -enable-checker alpha.core.TestAfterDivZero \
"

scan-build \
    $CHECKERS \
    ./configure

scan-build \
    $CHECKERS \
    make -j2 -k


# This one gives a false positive on every strcmp.
#    -enable-checker alpha.core.PointerSub

# Needs work
#  alpha.unix.MallocWithAnnotations ??
