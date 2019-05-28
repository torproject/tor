#!/bin/sh

# To use this script, build Tor with coverage enabled, and then say:
#  ./scripts/test/cov-test-determinism.sh run
#
# Let it run for a long time so it can run the tests over and over.  It
# will put their coverage outputs in coverage-raw/coverage-*/.
#
# Then say:
#  ./scripts/test/cov-test-determinism.sh check
#
# It will diff the other coverage outputs to the first one, and put their
# diffs in coverage-raw/diff-coverage-*.

run=0
check=0

if test "$1" = run; then
    run=1
elif test "$1" = check; then
    check=1
else
    echo "First use 'run' with this script, then use 'check'."
    exit 1
fi

if test "$run" = 1; then
    # same seed as in travis.yml
    TOR_TEST_RNG_SEED="636f766572616765"
    export TOR_TEST_RNG_SEED
    while true; do
        make reset-gcov
        CD=coverage-raw/coverage-$(date +%s)
        make -j5 check
        mkdir -p "$CD"
        ./scripts/test/coverage "$CD"
    done
fi

if test "$check" = 1; then
    cd coverage-raw || exit 1

    FIRST="$(find . -name "coverage-*" -type d | head -1)"
    rm -f A
    ln -sf "$FIRST" A
    for dir in coverage-*; do
        rm -f B
        ln -sf "$dir" B
        ../scripts/test/cov-diff A B > "diff-$dir"
    done
fi
