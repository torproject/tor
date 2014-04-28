#!/bin/sh
# Copyright 2014 The Tor Project, Inc
# See LICENSE for licensing information
#
# This script is used for running a bunch of clang scan-build checkers
# on Tor.  
#
# It has hardwired paths for Nick's desktop at the moment.

CHECKERS="\
    --use-analyzer=/opt/clang-3.4/bin/clang \
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
    -enable-checker security.insecureAPI.strcpy
"

/opt/clang-3.4/bin/scan-build/scan-build \
    $CHECKERS \
    --use-analyzer=/opt/clang-3.4/bin/clang \
    ./configure

/opt/clang-3.4/bin/scan-build/scan-build \
    $CHECKERS \
    --use-analyzer=/opt/clang-3.4/bin/clang \
    make -j2


# Haven't tried this yet.
#    -enable-checker alpha.unix.PthreadLock

# This one gives a false positive on every strcmp.
#    -enable-checker alpha.core.PointerSub

# This one hates it when we stick a nonzero const in a pointer.
#    -enable-checker alpha.core.FixedAddr

# This one crashes sometimes for me.
#    -enable-checker alpha.deadcode.IdempotentOperations
