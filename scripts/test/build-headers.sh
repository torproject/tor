#!/bin/bash
# Copyright 2019  The Tor Project, Inc.
# See LICENSE for licensing information.

set -e
set -o pipefail

# Script to set us up for building all of our headers by themselves
#
# This script makes a directory called "test_headers", then populates
# it with one C file for each header.  The C file defines all of the
# PRIVATE, INTERNAL, and EXPOSE macros listed in the header. If the
# header depends on TOR_UNIT_TESTS, this script creates another C file,
# which defines TOR_UNIT_TESTS, in addition to the other defines.
#
# This script also creates a prefix header, which contains common
# header dependencies. Over time, we will reduce the number of headers
# included in the prefix header.
#
# Finally, each C file also includes the target header.
#
# The script also makes a Makefile in this directory, that tries to
# build every C file it generates. This script uses the Makefile to
# build all the generated C files. The build depends on the
# warning_flags file created by configure.
#
# At the moment, some headers fail to compile by themselves. This
# script uses an exceptions file that allows some headers to fail.
# Over time, we will reduce the number of headers in the exceptions
# file.
#
# After building all the C files, this script reports the number of
# successful and failed headers, and any unexpected failures.

EXIT_STATUS=0

# The first argument is $abs_top_srcdir, defaulting to the current directory.
SOURCE_DIR="${1:-.}"
# The second argument is $abs_top_builddir, defaulting to the current
# directory.
BUILD_DIR="${2:-.}"
# The third argument is $MAKE, defaulting to "make"
MAKE_CMD="${3:-make}"
# The remaining arguments are an optional list of file names, used to filter
# the test files. We'll access them using "$*"
shift
shift
shift

if test $# -gt 0; then
    echo "Skipping headers that are not in '$*'."
fi

# Paths in the Makefile are relative to $TEST_DIR
TEST_DIR="${BUILD_DIR}"/test_headers
# Headers that are allowed to fail
EXCEPTIONS_FILE="$SOURCE_DIR"/scripts/test/build-headers-exceptions.txt

# Paths in this script must be absolute
# If relative paths are used in this script, they will cause permissions
# errors
RELATIVE_PATH_FAIL_DIR=$(mktemp -d -t build_headers_path_fail_XXXXXX)
cd "$RELATIVE_PATH_FAIL_DIR"
chmod a-rwx "$RELATIVE_PATH_FAIL_DIR"

mkdir -p "$TEST_DIR"

cat > "${TEST_DIR}"/prefix.h <<EOF
/*
 * List of tor prefix headers
 * We include this header before testing that other headers can compile by
 * themselves. Other headers can expect these headers to be included in
 * every file, before the header itself is included.
 */
#include "orconfig.h"

/* TODO: remove these dependencies */
#include "lib/cc/torint.h"
#include "lib/testsupport/testsupport.h"
EOF

# Includes are relative to $abs_top_srcdir{,/src,/src/ext}
# We also add $BUILD_DIR to the include path, for test_headers/prefix.h
# (We don't add $TEST_DIR to the include path, to avoid including any other
# generated files.)
MAKEFILE_PATH="${TEST_DIR}"/Makefile
cat > "$MAKEFILE_PATH" <<EOF

all:
	rm -f header_*.txt
	\$(MAKE) objects

update-exceptions:
	\$(MAKE) all
	LC_ALL=C sort header_fail.txt > "$EXCEPTIONS_FILE"

.c.o:
	echo "\$<" >> header_all.txt
	if gcc -c \
	    -Wall -Werror @"${BUILD_DIR}"/warning_flags -Wno-unused-function \
	    -I "${SOURCE_DIR}" -I "${SOURCE_DIR}"/src \
	    -I "${SOURCE_DIR}"/src/ext -I "${SOURCE_DIR}"/src/ext/trunnel \
	    -I "${BUILD_DIR}" \
	    -o "\$@" "\$<"; then \
	    echo "\$<" >> header_success.txt; \
	else \
	    echo "\$<" >> header_fail.txt; \
	fi
EOF

add_obj()
{
    NAME="$1"
    HDR="$2"
    cat >> "$MAKEFILE_PATH" <<EOF
objects: ${NAME}.o
${NAME}.o: ${NAME}.c ${HDR} prefix.h
EOF
}

# We deliberately skip win32: it only contains a Windows orconfig.h
for hdr in $(cd "${SOURCE_DIR}"/src \
                 && find lib core feature app test tools -name '*.h'); do
    hdr_path="${SOURCE_DIR}"/src/"${hdr}"
    name=$(basename "$hdr" .h)
    tc_name="${name}"_h
    tc_path="${TEST_DIR}"/"$tc_name".c

    if test $# -gt 0; then
        name_h=$(basename "$hdr")
        build_header=no
        for use_h in "$@"; do
            if test "$name_h" == "$use_h"; then
                build_header=yes
            fi
        done
        if test "$build_header" == no; then
            continue;
        fi
    fi

    grep \
        '^ *# *if\(def *\| .*defined(\)[A-Z_]*\(PRIVATE\|INTERNAL\|EXPOSE\)[A-Z_]*' \
        "$hdr_path" \
        | sed -e \
        's/.*[ (]\([A-Z_]*\(PRIVATE\|INTERNAL\|EXPOSE\)[A-Z_]*\).*/#define \1/' \
        | LC_ALL=C sort -u > \
               "$tc_path" || true # ignore grep's exit status

    cat >> "$tc_path" <<EOF

#include "test_headers/prefix.h"
#include "$hdr"

EOF

    add_obj "$tc_name" "$hdr_path"

    if grep -q \
            '^ *# *if\(def *\| .*defined(\)TOR_UNIT_TESTS' "$hdr_path"; then
        tuc_name="${name}"_hu
        tuc_path="${TEST_DIR}"/"$tuc_name".c
        echo "#define TOR_UNIT_TESTS" > "$tuc_path"
        cat "$tc_path" >> "$tuc_path"
        add_obj "$tuc_name" "$hdr_path"
    fi

done

"$MAKE_CMD" -C "$TEST_DIR"
all_count=$(grep -c '^.*$' "${TEST_DIR}"/header_all.txt) || true
success_count=$(grep -c '^.*$' "${TEST_DIR}"/header_success.txt) || true
fail_count=$(grep -c '^.*$' "${TEST_DIR}"/header_fail.txt) || true
exception_count=$(grep -c '^.*$' "$EXCEPTIONS_FILE") || true

LC_ALL=C sort "${TEST_DIR}"/header_fail.txt \
      > "${TEST_DIR}"/header_fail_sorted.txt

# Report success and failure counts
echo "Compiled each tor-owned header by itself:"
echo "${success_count}/${all_count} succeeded"
echo "${fail_count}/${all_count} failed"
# Don't show xfail if we only built some headers
if test $# -eq 0; then
    echo "${exception_count}/${all_count} expected to fail"
fi

# Work around sort that ignores LC_ALL, or uses a different sort order
# to the exceptions file.
LC_ALL=C sort "$EXCEPTIONS_FILE" \
      > "${TEST_DIR}"/header_exceptions_sorted.txt

# Report differences
diff -u \
     "${TEST_DIR}"/header_exceptions_sorted.txt \
     "${TEST_DIR}"/header_fail_sorted.txt \
     > "${TEST_DIR}"/header_fail_diff.txt || true
# Don't show differences if we only built some headers
if test $# -eq 0; then
    if test -s "${TEST_DIR}"/header_fail_diff.txt; then
        echo "Differences between expected failures and actual failures:"
        cat "${TEST_DIR}"/header_fail_diff.txt
    fi
fi

# Check for errors
if test "$fail_count" -gt "$exception_count"; then
    echo "Too many header compilation failures!"
    echo "Expected ${exception_count}, got ${fail_count}."
    EXIT_STATUS=1
fi

# Ignore headers that we expected to fail, but actually didn't fail
# (Some configurations disable some failing code.)
grep '^+[^ ]*c$' "${TEST_DIR}"/header_fail_diff.txt \
     > "${TEST_DIR}"/header_fail_unexp.txt || true
unexpected_fail_count=$(grep -c '^.*$' "${TEST_DIR}"/header_fail_unexp.txt) \
    || true
if test "$unexpected_fail_count" -gt 0; then
    echo "${unexpected_fail_count} unexpected header compilation failures:"
    cat "${TEST_DIR}"/header_fail_unexp.txt
    EXIT_STATUS=1
fi

rmdir "$RELATIVE_PATH_FAIL_DIR"

exit $EXIT_STATUS
