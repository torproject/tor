#!/bin/sh

TEST_NET_RETRIES=${TEST_NET_RETRIES:-3}

n_tries=0
test_net_okay=0

while [ "${n_tries}" -lt "${TEST_NET_RETRIES}" ]; do
    n_tries=$((n_tries + 1))
    # shellcheck disable=SC2086
    if "${top_srcdir:-.}/src/test/test-network.sh" ${TEST_NETWORK_FLAGS}; then
	echo "Chutney ran successfully after ${n_tries} attempt(s)."
	test_net_okay=1
	break
    fi
    echo "Chutney failed on attempt ${n_tries}/${TEST_NET_RETRIES}."
done;

if [ "$test_net_okay" != 1 ]; then
    echo "Too many chutney failures; failing."
    exit 1;
fi

exit 0
