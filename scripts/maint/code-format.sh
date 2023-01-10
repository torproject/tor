#!/usr/bin/env bash
# Copyright 2020, The Tor Project, Inc.
# See LICENSE for licensing information.

#
# DO NOT COMMIT OR MERGE CODE THAT IS RUN THROUGH THIS TOOL YET.
#
# WE ARE STILL DISCUSSING OUR DESIRED STYLE AND ITERATING ON IT.
#     (12 Feb 2020)
#

# This script runs "clang-format" and "codetool" in sequence over each of its
# arguments.  It either replaces the original, or says whether anything has
# changed, depending on its arguments.
#
# We can't just use clang-format directly, since we also want to use codetool
# to reformat a few things back to how we want them, and we want avoid changing
# the mtime on files that didn't actually change.
#
# Use "-i" to edit the file in-place.
# Use "-c" to exit with a nonzero exit status if any file needs to change.
# Use "-d" to emit diffs.
#
# The "-a" option tells us to run over every Tor source file.
# The "-v" option tells us to be verbose.

set -e

ALL=0
GITDIFF=0
GITIDX=0
DIFFMODE=0
CHECKMODE=0
CHANGEMODE=0

SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(dirname "$0")
SRC_DIR="${SCRIPT_DIR}/../../src"

function usage() {
    echo "$SCRIPT_NAME [-h] [-c|-d|-i] [-v] [-a|-G|files...]"
    echo
    echo "  flags:"
    echo "    -h: show this help text"
    echo "    -c: check whether files are correctly formatted"
    echo "    -d: print a diff for the changes that would be applied"
    echo "    -i: change files in-place"
    echo "    -a: run over all the C files in Tor"
    echo "    -v: verbose mode"
    echo "    -g: look at the files that have changed in git."
    echo "    -G: look at the files that are staged for the git commit."
    echo
    echo "EXAMPLES"
    echo
    echo "  $SCRIPT_NAME -a -i"
    echo "     rewrite every file in place, whether it has changed or not."
    echo "  $SCRIPT_NAME -a -d"
    echo "     as above, but only display the changes."
    echo "  $SCRIPT_NAME -g -i"
    echo "     update every file that you have changed in the git working tree."
    echo "  $SCRIPT_NAME -G -c"
    echo "     exit with an error if any staged changes are not well-formatted."
}

FILEARGS_OK=1

while getopts "acdgGhiv" opt; do
    case "$opt" in
        h) usage
           exit 0
           ;;
        a) ALL=1
           FILEARGS_OK=0
           ;;
        g) GITDIFF=1
           FILEARGS_OK=0
           ;;
        G) GITIDX=1
           FILEARGS_OK=0
           ;;
        c) CHECKMODE=1
           ;;
        d) DIFFMODE=1
           ;;
        i) CHANGEMODE=1
           ;;
        v) VERBOSE=1
           ;;
        *) echo
           usage
           exit 1
           ;;
    esac
done
# get rid of the flags; keep the filenames.
shift $((OPTIND - 1))

# Define a verbose function.
if [[ $VERBOSE = 1 ]]; then
    function note()
    {
        echo "$@"
    }
else
    function note()
    {
        true
    }
fi

# We have to be in at least one mode, or we can't do anything
if [[ $CHECKMODE = 0 && $DIFFMODE = 0 && $CHANGEMODE = 0 ]]; then
    echo "Nothing to do. You need to specify -c, -d, or -i."
    echo "Try $SCRIPT_NAME -h for more information."
    exit 0
fi

# We don't want to "give an error if anything would change" if we're
# actually trying to change things.
if [[ $CHECKMODE = 1 && $CHANGEMODE = 1 ]]; then
    echo "It doesn't make sense to use -c and -i together."
    exit 0
fi
# It doesn't make sense to look at "all files" and "git files"
if [[ $((ALL + GITIDX + GITDIFF)) -gt 1 ]]; then
    echo "It doesn't make sense to use more than one of -a, -g, or -G together."
    exit 0
fi

if [[ $FILEARGS_OK = 1 ]]; then
    # The filenames are on the command-line.
    INPUTS=("${@}")
else
    if [[ "$#" != 0 ]]; then
        echo "Can't use -a, -g, or  -G with additional command-line arguments."
        exit 1
    fi
fi

if [[ $ALL = 1 ]]; then
    # We're in "all" mode -- use find(1) to find the filenames.
    mapfile -d '' INPUTS < <(find "${SRC_DIR}"/{lib,core,feature,app,test,tools} -name '[^.]*.[ch]' -print0)
elif [[ $GITIDX = 1 ]]; then
    # We're in "git index" mode -- use git diff --cached to find the filenames
    # that are changing in the index, then strip out the ones that
    # aren't C.
    mapfile INPUTS < <(git diff --name-only --cached --diff-filter=AMCR | grep '\.[ch]$')
elif [[ $GITDIFF = 1 ]]; then
    # We are in 'git diff' mode -- we want everything that changed, including
    # the index and the working tree.
    #
    # TODO: There might be a better way to do this.
    mapfile INPUTS < <(git diff --name-only --cached --diff-filter=AMCR | grep '\.[ch]$'; git diff --name-only --diff-filter=AMCR | grep '\.[ch]$' )
fi

if [[ $GITIDX = 1 ]]; then
    # If we're running in git mode, we need to stash all the changes that
    # we don't want to look at.  This is necessary even though we're only
    # looking at the changed files, since we might have the file only
    # partially staged.
    note "Stashing unstaged changes"
    git stash -q --keep-index
    # For some reasons, shellcheck is not seeing that we can call this
    # function from the trap below.
    # shellcheck disable=SC2317
    function restoregit() {
        note "Restoring git state"
        git stash pop -q
    }
else
    # For some reasons, shellcheck is not seeing that we can call this
    # function from the trap below.
    # shellcheck disable=SC2317
    function restoregit() {
        true
    }
fi

ANY_CHANGED=0

tmpfname=""

#
# Set up a trap handler to make sure that on exit, we remove our
# tmpfile and un-stash the git environment (if appropriate)
#
trap 'if [ -n "${tmpfname}" ]; then rm -f "${tmpfname}"; fi; restoregit' 0

for fname in "${INPUTS[@]}"; do
    note "Inspecting $fname..."
    tmpfname="${fname}.$$.clang_fmt.tmp"
    rm -f "${tmpfname}"
    clang-format --style=file "${fname}" > "${tmpfname}"
    "${SCRIPT_DIR}/codetool.py" "${tmpfname}"

    changed=not_set

    if [[ $DIFFMODE = 1 ]]; then
        # If we're running diff for its output, we can also use it
        # to compare the files.
        if diff -u "${fname}" "${tmpfname}"; then
            changed=0
        else
            changed=1
        fi
    else
        # We aren't running diff, so we have to compare the files with cmp.
        if cmp "${fname}" "${tmpfname}" >/dev/null 2>&1; then
            changed=0
        else
            changed=1
        fi
    fi

    if [[ $changed = 1 ]]; then
        note "Found a change in $fname"
        ANY_CHANGED=1

        if [[ $CHANGEMODE = 1 ]]; then
            mv "${tmpfname}" "${fname}"
        fi
    fi

    rm -f "${tmpfname}"
done

exitcode=0

if [[ $CHECKMODE = 1 ]]; then
    if [[ $ANY_CHANGED = 1 ]]; then
        note "Found at least one misformatted file; check failed"
        exitcode=1
    else
        note "No changes found."
    fi
fi

exit $exitcode
