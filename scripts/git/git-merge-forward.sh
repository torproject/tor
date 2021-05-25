#!/usr/bin/env bash

SCRIPT_NAME=$(basename "$0")

function usage()
{
  echo "$SCRIPT_NAME [-h] [-n] [-t <test-branch-prefix> [-u]]"
  echo
  echo "  arguments:"
  echo "   -h: show this help text"
  echo "   -n: dry run mode"
  echo "       (default: run commands)"
  echo "   -t: test branch mode: create new branches from the commits checked"
  echo "       out in each maint directory. Call these branches prefix_035,"
  echo "       prefix_040, ... , prefix_main."
  echo "       (default: merge forward maint-*, release-*, and main)"
  echo "   -u: in test branch mode, if a prefix_* branch already exists,"
  echo "       skip creating that branch. Use after a merge error, to"
  echo "       restart the merge forward at the first unmerged branch."
  echo "       (default: if a prefix_* branch already exists, fail and exit)"
  echo
  echo " env vars:"
  echo "   required:"
  echo "   TOR_FULL_GIT_PATH: where the git repository directories reside."
  echo "       You must set this env var, we recommend \$HOME/git/"
  echo "       (default: fail if this env var is not set;"
  echo "       current: $GIT_PATH)"
  echo
  echo "   optional:"
  echo "   TOR_MASTER: the name of the directory containing the tor.git clone"
  echo "       The primary tor git directory is \$GIT_PATH/\$TOR_MASTER"
  echo "       (default: tor; current: $TOR_MASTER_NAME)"
  echo "   TOR_WKT_NAME: the name of the directory containing the tor"
  echo "       worktrees. The tor worktrees are:"
  echo "       \$GIT_PATH/\$TOR_WKT_NAME/{maint-*,release-*}"
  echo "       (default: tor-wkt; current: $TOR_WKT_NAME)"
  echo "   we recommend that you set these env vars in your ~/.profile"
}

#################
# Configuration #
#################

# Don't change this configuration - set the env vars in your .profile

# Where are all those git repositories?
GIT_PATH=${TOR_FULL_GIT_PATH:-"FULL_PATH_TO_GIT_REPOSITORY_DIRECTORY"}
# The main branch git repository directory from which all the worktree have
# been created.
TOR_MASTER_NAME=${TOR_MASTER_NAME:-"tor"}
# The worktrees location (directory).
TOR_WKT_NAME=${TOR_WKT_NAME:-"tor-wkt"}

##########################
# Git branches to manage #
##########################

# The branches and worktrees need to be modified when there is a new branch,
# and when an old branch is no longer supported.

# Configuration of the branches that needs merging. The values are in order:
#   (0) current maint/release branch name
#   (1) previous maint/release name to merge into (0)
#         (only used in merge forward mode)
#   (2) Full path of the git worktree
#   (3) current branch suffix
#         (maint branches only, only used in test branch mode)
#   (4) previous test branch suffix to merge into (3)
#         (maint branches only, only used in test branch mode)
#
# Merge forward example:
#   $ cd <PATH/TO/WORKTREE> (2)
#   $ git checkout maint-0.3.5 (0)
#   $ git pull
#   $ git merge maint-0.3.4 (1)
#
# Test branch example:
#   $ cd <PATH/TO/WORKTREE> (2)
#   $ git checkout -b ticket99999_035 (3)
#   $ git checkout maint-0.3.5 (0)
#   $ git pull
#   $ git checkout ticket99999_035
#   $ git merge maint-0.3.5
#   $ git merge ticket99999_034 (4)
#
# First set of arrays are the maint-* branch and then the release-* branch.
# New arrays need to be in the WORKTREE= array else they aren't considered.
#
# Only used in test branch mode
# We create a test branch for the earliest maint branch.
# But it's the earliest maint branch, so we don't merge forward into it.
# Since we don't merge forward into it, the second and fifth items must be
# blank ("").

# origin that will be used to fetch the updates. All the worktrees are created
# from that repository.
ORIGIN_PATH="$GIT_PATH/$TOR_MASTER_NAME"

#######################
# Argument processing #
#######################

# Controlled by the -n option. The dry run option will just output the command
# that would have been executed for each worktree.
DRY_RUN=0

# Controlled by the -t <test-branch-prefix> option. The test branch base
# name option makes git-merge-forward.sh create new test branches:
# <tbbn>_035, <tbbn>_040, ... , <tbbn>_main, and merge forward.
TEST_BRANCH_PREFIX=

# Controlled by the -u option. The use existing option checks for existing
# branches with the <test-branch-prefix>, and checks them out, rather than
# creating a new branch.
USE_EXISTING=0

while getopts "hnt:u" opt; do
  case "$opt" in
    h) usage
       exit 0
       ;;
    n) DRY_RUN=1
       echo "    *** DRY RUN MODE ***"
       ;;
    t) TEST_BRANCH_PREFIX="$OPTARG"
       echo "    *** CREATING TEST BRANCHES: ${TEST_BRANCH_PREFIX}_nnn ***"
       ;;
    u) USE_EXISTING=1
       echo "    *** USE EXISTING TEST BRANCHES MODE ***"
       ;;
    *)
       echo
       usage
       exit 1
       ;;
  esac
done

###########################
# Git worktrees to manage #
###########################

set -e
if [ -z "$TEST_BRANCH_PREFIX" ]; then
  # maint/release merge mode
  eval "$(git-list-tor-branches.sh -m)"
  # Remove first element: we don't merge forward into it.
  WORKTREE=( "${WORKTREE[@]:1}" )
else
  eval "$(git-list-tor-branches.sh -m -R)"
fi
set +e

COUNT=${#WORKTREE[@]}

#############
# Constants #
#############

# Control characters
CNRM=$'\x1b[0;0m'   # Clear color

# Bright color
BGRN=$'\x1b[1;32m'
BBLU=$'\x1b[1;34m'
BRED=$'\x1b[1;31m'
BYEL=$'\x1b[1;33m'
IWTH=$'\x1b[3;37m'

# Strings for the pretty print.
MARKER="${BBLU}[${BGRN}+${BBLU}]${CNRM}"
SUCCESS="${BGRN}success${CNRM}"
FAILED="${BRED}failed${CNRM}"

####################
# Helper functions #
####################

# Validate the given returned value (error code), print success or failed. The
# second argument is the error output in case of failure, it is printed out.
# On failure, this function exits.
function validate_ret
{
  if [ "$1" -eq 0 ]; then
    printf "%s\\n" "$SUCCESS"
  else
    printf "%s\\n" "$FAILED"
    printf "    %s" "$2"
    exit 1
  fi
}

# Switch to the given branch name.
function switch_branch
{
  local cmd="git checkout '$1'"
  printf "  %s Switching branch to %s..." "$MARKER" "$1"
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Checkout a new branch with the given branch name.
function new_branch
{
  local cmd="git checkout -b '$1'"
  printf "  %s Creating new branch %s..." "$MARKER" "$1"
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Switch to an existing branch, or checkout a new branch with the given
# branch name.
function switch_or_new_branch
{
  local cmd="git rev-parse --verify '$1'"
  if [ $DRY_RUN -eq 0 ]; then
    # Call switch_branch if there is a branch, or new_branch if there is not
    msg=$( eval "$cmd" 2>&1 )
    RET=$?
    if [ $RET -eq 0 ]; then
      # Branch: (commit id)
      switch_branch "$1"
    elif [ $RET -eq 128 ]; then
      # Not a branch: "fatal: Needed a single revision"
      new_branch "$1"
    else
      # Unexpected return value
      validate_ret $RET "$msg"
    fi
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}, then depending on the result:"
    switch_branch "$1"
    new_branch "$1"
  fi
}

# Pull the given branch name.
function pull_branch
{
  local cmd="git pull"
  printf "  %s Pulling branch %s..." "$MARKER" "$1"
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Merge the given branch name ($1) into the current branch ($2).
function merge_branch
{
  local cmd="git merge --no-edit '$1'"
  printf "  %s Merging branch %s into %s..." "$MARKER" "$1" "$2"
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Merge origin/(branch name) into the current branch.
function merge_branch_origin
{
  local cmd="git merge --ff-only 'origin/$1'"
  printf "  %s Merging branch origin/%s..." "$MARKER" "$1"
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Go into the worktree repository.
function goto_repo
{
  if [ ! -d "$1" ]; then
    echo "  $1: Not found. Stopping."
    exit 1
  fi
  cd "$1" || exit
}

# Fetch the origin. No arguments.
function fetch_origin
{
  local cmd="git fetch origin"
  printf "  %s Fetching origin..." "$MARKER"
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

###############
# Entry point #
###############

# First, fetch the origin.
goto_repo "$ORIGIN_PATH"
fetch_origin

# Go over all configured worktree.
for ((i=0; i<COUNT; i++)); do
  current=${!WORKTREE[$i]:0:1}
  previous=${!WORKTREE[$i]:1:1}
  repo_path=${!WORKTREE[$i]:2:1}
  # default to merge forward mode
  test_current=
  test_previous=
  target_current="$current"
  target_previous="$previous"
  if [ "$TEST_BRANCH_PREFIX" ]; then
    test_current_suffix=${!WORKTREE[$i]:3:1}
    test_current=${TEST_BRANCH_PREFIX}${test_current_suffix}
    # the current test branch, if present, or maint/release branch, if not
    target_current="$test_current"
    test_previous_suffix=${!WORKTREE[$i]:4:1}
    if [ "$test_previous_suffix" ]; then
      test_previous=${TEST_BRANCH_PREFIX}${test_previous_suffix}
      # the previous test branch, if present, or maint/release branch, if not
      target_previous="$test_previous"
    fi
  fi

  printf "%s Handling branch \\n" "$MARKER" "${BYEL}$target_current${CNRM}"

  # Go into the worktree to start merging.
  goto_repo "$repo_path"
  if [ "$test_current" ]; then
    if [ $USE_EXISTING -eq 0 ]; then
      # Create a test branch from the currently checked-out branch/commit
      # Fail if it already exists
      new_branch "$test_current"
    else
      # Switch if it exists, or create if it does not
      switch_or_new_branch "$test_current"
    fi
  fi
  # Checkout the current maint/release branch
  switch_branch "$current"
  # Update the current maint/release branch with an origin merge to get the
  # latest updates
  merge_branch_origin "$current"
  if [ "$test_current" ]; then
    # Checkout the test branch
    switch_branch "$test_current"
    # Merge the updated maint branch into the test branch
    merge_branch "$current" "$test_current"
  fi
  # Merge the previous branch into the target branch
  # Merge Forward Example:
  #   merge maint-0.3.5 into maint-0.4.0.
  # Test Branch Example:
  #   merge bug99999_035 into bug99999_040.
  # Skip the merge if the previous branch does not exist
  # (there's nothing to merge forward into the oldest test branch)
  if [ "$target_previous" ]; then
    merge_branch "$target_previous" "$target_current"
  fi
done
