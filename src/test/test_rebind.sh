#!/bin/sh

exitcode=0

"${PYTHON:-python}" "${abs_top_srcdir:-.}/src/test/test_rebind.py" "${TESTING_TOR_BINARY}" || exitcode=1

exit ${exitcode}
