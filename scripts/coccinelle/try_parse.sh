#!/bin/sh

# Echo the name of every argument of this script that is not "perfect"
# according to coccinelle's --parse-c.

top="$(dirname "$0")/../.."

exitcode=0

for fn in "$@"; do

    if spatch -macro_file_builtins "$top"/scripts/coccinelle/tor-coccinelle.h \
              -I "$top" -I "$top"/src -I "$top"/ext --defined COCCI \
              --parse-c "$fn" \
              2>/dev/null | grep "perfect = 1" > /dev/null; then
        : # it's perfect
    else
        echo "$fn"
        if test "${VERBOSE}" != ""; then
            spatch -macro_file_builtins "$top"/scripts/coccinelle/tor-coccinelle.h \
                   -I "$top" -I "$top"/src -I "$top"/ext --defined COCCI \
                   --parse-c "$fn"
        fi
        exitcode=1
    fi

done

exit "$exitcode"
