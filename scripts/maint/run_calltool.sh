#!/bin/sh

# You can find calltool at https://gitweb.torproject.org/user/nickm/calltool.git

set -e

if test "x$CALLTOOL_PATH" != "x"; then
    PYTHONPATH="${CALLTOOL_PATH}:${PYTHONPATH}"
    export PYTHONPATH
fi

mkdir -p callgraph

SUBITEMS="fn_graph fn_invgraph fn_scc fn_scc_weaklinks module_graph module_invgraph module_scc module_scc_weaklinks"

for calculation in $SUBITEMS; do
    echo "======== $calculation"
    python -m calltool "$calculation" > callgraph/"$calculation"
done

cat <<EOF > callgraph/README
This directory holds output from calltool, as run on Tor.  For more
information about each of these files, see the NOTES and README files in
the calltool distribution.

You can find calltool at
    https://gitweb.torproject.org/user/nickm/calltool.git
EOF

