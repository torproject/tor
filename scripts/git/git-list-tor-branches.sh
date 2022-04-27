#!/usr/bin/env bash

# Script to be used by other git scripts, and provide a single place
# that lists our supported branches.  To change which branches are
# supported, look at the end of the file that says 'edit here'.

SCRIPT_NAME=$(basename "$0")

function usage()
{
    echo "$SCRIPT_NAME [-h] [-l|-s|-b|-m] [-R|-M]"
    echo
    echo "  arguments:"
    echo "   -h: show this help text"
    echo
    echo "   -l: list the active tor branches (default)"
    echo "   -s: list the suffixes to be used with the active tor branches"
    echo "   -b: write bash code setting WORKTREE to an array of ( branch path ) arrays"
    echo "   -m: write bash code setting WORKTREE to an array of"
    echo "       ( branch parent path suffix parent_suffix ) arrays"
    echo
    echo "   -R: omit release branches."
    echo "   -M: omit maint branches."
}

# list : just a list of branch names.
# branch_path : For git-setup-dirs.sh and git-pull-all.sh
# suffix: write a list of suffixes.
# merge: branch, upstream, path, suffix, upstream suffix.
mode="list"
skip_maint_branches="no"
skip_release_branches="no"

while getopts "hblmsRM" opt ; do
    case "$opt" in
        h) usage
           exit 0
           ;;
        b) mode="branch_path"
           ;;
        l) mode="list"
           ;;
        s) mode="suffix"
           ;;
        m) mode="merge"
           ;;
        M) skip_maint_branches="yes"
           ;;
        R) skip_release_branches="yes"
           ;;
        *) echo "Unknown option"
           exit 1
           ;;
    esac
done

all_branch_vars=()

prev_maint_branch=""
prev_maint_suffix=""

branch() {
    # The name of the branch. (Supplied by caller)  Ex: maint-0.4.3
    brname="$1"

    # The name of the branch with no dots. Ex: maint-043
    brname_nodots="${brname//./}"
    # The name of the branch with no dots, and _ instead of -. Ex: maint_043
    brname_nodots_uscore="${brname_nodots//-/_}"
    # Name to use for a variable to represent the branch. Ex: MAINT_043
    varname="${brname_nodots_uscore^^}"

    is_maint="no"

    # suffix: a suffix to place at the end of branches we generate with respect
    # to this branch.  Ex: _043

    # location: where the branch can be found.

    if [[ "$brname" == "main" ]]; then
        suffix="_main"
        location="\$GIT_PATH/\$TOR_MASTER_NAME"
    elif [[ "$brname" =~ ^maint- ]]; then
        suffix="_${brname_nodots#maint-}"
        location="\$GIT_PATH/\$TOR_WKT_NAME/$brname"
        is_maint="yes"
        if [[ "$skip_maint_branches" = "yes" ]]; then
            return
        fi
    elif [[ "$brname" =~ ^release- ]]; then
        suffix="_r${brname_nodots#release-}"
        location="\$GIT_PATH/\$TOR_WKT_NAME/$brname"

        if [[ "$skip_release_branches" = "yes" ]]; then
            return
        fi
    else
        echo "Unrecognized branch type '${brname}'" >&2
        exit 1
    fi

    all_branch_vars+=("$varname")

    # Now emit the per-branch information
    if [[ "$mode" == "branch_path" ]]; then
        echo "${varname}=( \"$brname\" \"$location\" )"
    elif [[ "$mode" == "merge" ]]; then
        echo "${varname}=( \"$brname\" \"$prev_maint_branch\" \"$location\" \"$suffix\" \"$prev_maint_suffix\" )"
    elif [[ "$mode" == "list" ]]; then
        echo "$brname"
    elif [[ "$mode" == "suffix" ]]; then
        echo "$suffix"
    else
        echo "unknown mode $mode" >&2
        exit 1
    fi

    if [[ "$is_maint" == "yes" ]]; then
        prev_maint_branch="$brname"
        prev_maint_suffix="$suffix"
    fi
}

finish() {
    if [[ "$mode" == branch_path ]] || [[ "$mode" == merge ]]; then
        echo "WORKTREE=("
        for v in "${all_branch_vars[@]}"; do
            echo "  ${v}[@]"
        done
        echo ")"
    elif [[ "$mode" == list ]] || [[ "$mode" == suffix ]]; then
        # nothing to do
        :
    else
        echo "unknown mode $mode" >&2
        exit 1
    fi
}

# ==============================
# EDIT HERE
# ==============================
# List of all branches.  These must be in order, from oldest to newest, with
# maint before release.

branch maint-0.4.5
branch release-0.4.5

branch maint-0.4.6
branch release-0.4.6

branch maint-0.4.7
branch release-0.4.7

branch main

finish
