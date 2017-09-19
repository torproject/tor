#!/bin/sh
# Copyright 2014 The Tor Project, Inc
# See LICENSE for licensing information
#
# This script is used for running a bunch of clang scan-build checkers
# on Tor.

# These don't seem to cause false positives in our code, so let's turn
# them on.
CHECKERS="\
    -enable-checker alpha.core.CallAndMessageUnInitRefArg \
    -enable-checker alpha.core.CastToStruct \
    -enable-checker alpha.core.Conversion \
    -enable-checker alpha.core.FixedAddr \
    -enable-checker alpha.core.IdenticalExpr \
    -enable-checker alpha.core.PointerArithm \
    -enable-checker alpha.core.SizeofPtr \
    -enable-checker alpha.core.TestAfterDivZero \
    -enable-checker alpha.security.MallocOverflow \
    -enable-checker alpha.security.ReturnPtrRange \
    -enable-checker alpha.unix.BlockInCriticalSection \
    -enable-checker alpha.unix.Chroot \
    -enable-checker alpha.unix.PthreadLock \
    -enable-checker alpha.unix.PthreadLock \
    -enable-checker alpha.unix.SimpleStream \
    -enable-checker alpha.unix.Stream \
    -enable-checker alpha.unix.cstring.BufferOverlap \
    -enable-checker alpha.unix.cstring.NotNullTerminated \
    -enable-checker alpha.valist.CopyToSelf \
    -enable-checker alpha.valist.Uninitialized \
    -enable-checker alpha.valist.Unterminated \
    -enable-checker security.FloatLoopCounter \
    -enable-checker security.insecureAPI.strcpy \
"

# These have high false-positive rates.
EXTRA_CHECKERS="\
    -enable-checker alpha.security.ArrayBoundV2 \
    -enable-checker alpha.unix.cstring.OutOfBounds \
    -enable-checker alpha.core.CastSize \
"

# These don't seem to generate anything useful
NOISY_CHECKERS="\
    -enable-checker alpha.clone.CloneChecker \
    -enable-checker alpha.deadcode.UnreachableCode \
"

if test "x$SCAN_BUILD_OUTPUT" != "x"; then
   OUTPUTARG="-o $SCAN_BUILD_OUTPUT"
else
   OUTPUTARG=""
fi

scan-build \
    $CHECKERS \
    ./configure

scan-build \
    make clean

# Make this not get scanned for dead assignments, since it has lots of
# dead assignments we don't care about.
scan-build \
    $CHECKERS \
    -disable-checker deadcode.DeadStores \
    make -j5 -k ./src/ext/ed25519/ref10/libed25519_ref10.a

scan-build \
    $CHECKERS $OUTPUTARG \
    make -j5 -k

CHECKERS="\
"

# This one gives a false positive on every strcmp.
#    -enable-checker alpha.core.PointerSub

# Needs work
#    -enable-checker alpha.unix.MallocWithAnnotations
