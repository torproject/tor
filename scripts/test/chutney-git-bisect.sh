#!/usr/bin/env bash

# Compile tor and run chutney to find out if the current commit works
#
# Usage:
# # Copy the script, so it doesn't change during bisection
# cp scripts/test/chutney-git-bisect.sh .
# git bisect run \
#   ./chutney-git-bisect.sh [tries [build-dir [flavour [skip-flavour]]]]
#
# Runs chutney up to <tries> times (default 3), because some bugs involve race
# conditions.
# Changes to <build-dir> (default no cd) before running tests.
# Runs chutney network <flavour> (default make test-network-all) as the test.
# Skips the test if <skip-flavour> fails (default no skip).

CHUTNEY_TRIES=3
if [ -n "$1" ]; then
    CHUTNEY_TRIES="$1"
fi

if [ -n "$2" ]; then
    cd "$2" || exit
fi

CHUTNEY_TEST_CMD="make test-network-all"
if [ -n "$3" ]; then
    CHUTNEY_TEST_CMD="$CHUTNEY_PATH/tools/test-network.sh --flavour $3"
fi

CHUTNEY_SKIP_ON_FAIL_CMD="true"
if [ -n "$4" ]; then
    CHUTNEY_SKIP_ON_FAIL_CMD="$CHUTNEY_PATH/tools/test-network.sh --flavour $4"
fi

CHUTNEY_BUILD_CMD_OR="make src/or/tor src/tools/tor-gencert"
CHUTNEY_BUILD_CMD_APP="make src/app/tor src/tools/tor-gencert"
if ! ( $CHUTNEY_BUILD_CMD_APP || $CHUTNEY_BUILD_CMD_OR ) ; then
    echo "building '$CHUTNEY_BUILD_CMD_APP || $CHUTNEY_BUILD_CMD_OR' failed, skip"
    exit 125
fi

if ! $CHUTNEY_SKIP_ON_FAIL_CMD ; then
    echo "pre-condition '$CHUTNEY_SKIP_ON_FAIL_CMD' failed, skip"
    exit 125
fi

i=1
while [ "$i" -le "$CHUTNEY_TRIES" ]; do
    echo
    echo "Round $i/$CHUTNEY_TRIES:"
    echo
    if $CHUTNEY_TEST_CMD ; then
        echo "test '$CHUTNEY_TEST_CMD' succeeded after $i/$CHUTNEY_TRIES attempts, good"
        exit 0
    fi
    i=$((i+1))
done

i=$((i-1))
echo "test '$CHUTNEY_TEST_CMD' failed $i/$CHUTNEY_TRIES attempts, bad"
exit 1
