#!/usr/bin/env bash

SCRIPT_NAME=$(basename "$0")

usage()
{
  echo "$SCRIPT_NAME [-h] [-n]"
  echo
  echo "  arguments:"
  echo "   -h: show this help text"
  echo "   -n: dry run mode"
  echo "       (default: run commands)"
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
# The primary tor git repository directory from which all the worktree have
# been created.
TOR_MASTER_NAME=${TOR_MASTER_NAME:-"tor"}
# The worktrees location (directory).
TOR_WKT_NAME=${TOR_WKT_NAME:-"tor-wkt"}

##########################
# Git branches to manage #
##########################

set -e
eval "$(git-list-tor-branches.sh -b)"
set +e

# The main branch path has to be the main repository thus contains the
# origin that will be used to fetch the updates. All the worktrees are created
# from that repository.
ORIGIN_PATH="$GIT_PATH/$TOR_MASTER_NAME"

COUNT=${#WORKTREE[@]}

#######################
# Argument processing #
#######################

# Controlled by the -n option. The dry run option will just output the command
# that would have been executed for each worktree.
DRY_RUN=0

while getopts "hn" opt; do
  case "$opt" in
    h) usage
       exit 0
       ;;
    n) DRY_RUN=1
       echo "    *** DRY DRUN MODE ***"
       ;;
    *)
       echo
       usage
       exit 1
       ;;
  esac
done

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
SUCCESS="${BGRN}ok${CNRM}"
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
  local cmd="git checkout $1"
  printf "  %s Switching branch to %s..." "$MARKER" "$1"
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Pull the given branch name.
function merge_branch
{
  local cmd="git merge --ff-only origin/$1"
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
  printf "%s Fetching origin..." "$MARKER"
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Fetch tor-gitlab pull requests. No arguments.
function fetch_tor_gitlab
{
  local cmd="git fetch tor-gitlab"
  printf "%s Fetching tor-gitlab..." "$MARKER"
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

# Get into our origin repository.
goto_repo "$ORIGIN_PATH"

# First, fetch tor-gitlab
fetch_tor_gitlab

# Then, fetch the origin.
fetch_origin

# Go over all configured worktree.
for ((i=0; i<COUNT; i++)); do
  current=${!WORKTREE[$i]:0:1}
  repo_path=${!WORKTREE[$i]:1:1}

  printf "%s Handling branch %s\\n" "$MARKER" "${BYEL}$current${CNRM}"

  # Go into the worktree to start merging.
  goto_repo "$repo_path"
  # Checkout the current branch
  switch_branch "$current"
  # Update the current branch by merging the origin to get the latest.
  merge_branch "$current"
done
