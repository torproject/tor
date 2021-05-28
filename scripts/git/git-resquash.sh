#!/bin/sh
#
# Provides a convenient alias for "git rebase -i --autosquash --keep-root"
# on gits that have it, and a replacement on gits that don't.

set -e

PARENT="$1"

if test "$PARENT" = ""; then
    echo "You must specify the parent branch."
    exit 1
fi

# Can we use git rebase --keep-base?  Detect the git version to find out.
GITVER=$(git version)
if test "$(echo "$GITVER"|cut -d ' ' -f 1-2)" = "git version"; then
    # --keep-base was added in git 2.24.  Detect if we have that version.
    GITVER=$(echo "$GITVER" | cut -d ' ' -f 3)
    major=$(echo "$GITVER" | cut -d . -f 1)
    minor=$(echo "$GITVER" | cut -d . -f 2)
    if test "$major" -lt 2; then
        USE_KEEP_BASE=0
    elif test "$major" -eq 2 && test "$minor" -lt 24; then
        USE_KEEP_BASE=0
    else
        USE_KEEP_BASE=1
    fi
else
    # This isn't a git that reports its version in a way recognize; assume that
    # --keep-base will work
    USE_KEEP_BASE=1
fi

if test "$USE_KEEP_BASE" = "1" ; then
    exec git rebase -i --autosquash --keep-base "${PARENT}"
else
    REV=$(git log --reverse --format='%H' "${PARENT}..HEAD" | head -1)

    if test "${REV}" = ""; then
        echo "No changes here since ${PARENT}"
        exit 1
    fi

    exec git rebase -i --autosquash "${REV}^"
fi
