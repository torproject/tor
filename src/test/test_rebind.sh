#!/bin/sh

exitcode=0

"${PYTHON:-python}" "${abs_top_srcdir:-.}/src/test/test_rebind.py" ${abs_top_srcdir:-.}/src/or/tor || exitcode=1

exit ${exitcode}
