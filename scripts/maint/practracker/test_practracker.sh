#!/bin/sh

umask 077

TMPDIR=""
clean () {
  if [ -n "$TMPDIR" ] && [ -d "$TMPDIR" ]; then
    rm -rf "$TMPDIR"
  fi
}
trap clean EXIT HUP INT TERM

if test "${PRACTRACKER_DIR}" = "" ||
        test ! -e "${PRACTRACKER_DIR}/practracker.py" ; then
    PRACTRACKER_DIR=$(dirname "$0")
fi

TMPDIR="$(mktemp -d -t pracktracker.test.XXXXXX)"
if test -z "${TMPDIR}" || test ! -d "${TMPDIR}" ; then
    echo >&2 "mktemp failed."
    exit 1;
fi

DATA="${PRACTRACKER_DIR}/testdata"

run_practracker() {
    "${PYTHON:-python}" "${PRACTRACKER_DIR}/practracker.py" \
        --max-include-count=0 --max-file-size=0 --max-function-size=0 --terse \
        "${DATA}/" "$@";
}

echo "unit tests:"

"${PYTHON:-python}" "${PRACTRACKER_DIR}/practracker_tests.py" || exit 1

echo "ex0:"

run_practracker --exceptions "${DATA}/ex0.txt" > "${TMPDIR}/ex0-received.txt"

if cmp "${TMPDIR}/ex0-received.txt" "${DATA}/ex0-expected.txt" ; then
    echo "  OK"
else
    exit 1
fi

echo "ex1:"

run_practracker --exceptions "${DATA}/ex1.txt" > "${TMPDIR}/ex1-received.txt"

if cmp "${TMPDIR}/ex1-received.txt" "${DATA}/ex1-expected.txt" ;then
    echo "  OK"
else
    exit 1
fi
