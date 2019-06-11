#!/usr/bin/env bash

##############################
# Configuration (change me!) #
##############################

# The general setup that is suggested here is:
#
#   GIT_PATH = /home/<user>/git/
#     ... where the git repository directories resides.
#   TOR_MASTER_NAME = "tor"
#     ... which means that tor.git was cloned in /home/<user>/git/tor
#   TOR_WKT_NAME = "tor-wkt"
#     ... which means that the tor worktrees are in /home/<user>/git/tor-wkt

# Where are all those git repositories?
GIT_PATH=${TOR_FULL_GIT_PATH:-"FULL_PATH_TO_GIT_REPOSITORY_DIRECTORY"}
# The tor master git repository directory from which all the worktree have
# been created.
TOR_MASTER_NAME=${TOR_MASTER_NAME:-"tor"}
# The worktrees location (directory).
TOR_WKT_NAME=${TOR_WKT_NAME:-"tor-wkt"}

#########################
# End of configuration. #
#########################

# Configuration of the branches that needs merging. The values are in order:
#   (1) Branch name that we merge onto.
#   (2) Branch name to merge from. In other words, this is merge into (1)
#   (3) Full path of the git worktree.
#
# As an example:
#   $ cd <PATH/TO/WORKTREE> (3)
#   $ git checkout maint-0.3.5 (1)
#   $ git pull
#   $ git merge maint-0.3.4 (2)
#
# First set of arrays are the maint-* branch and then the release-* branch.
# New arrays need to be in the WORKTREE= array else they aren't considered.
MAINT_035=( "maint-0.3.5" "maint-0.2.9" "$GIT_PATH/$TOR_WKT_NAME/maint-0.3.5" )
MAINT_040=( "maint-0.4.0" "maint-0.3.5" "$GIT_PATH/$TOR_WKT_NAME/maint-0.4.0" )
MAINT_041=( "maint-0.4.1" "maint-0.4.0" "$GIT_PATH/$TOR_WKT_NAME/maint-0.4.1" )
MAINT_MASTER=( "master" "maint-0.4.1" "$GIT_PATH/$TOR_MASTER_NAME" )

RELEASE_029=( "release-0.2.9" "maint-0.2.9" "$GIT_PATH/$TOR_WKT_NAME/release-0.2.9" )
RELEASE_035=( "release-0.3.5" "maint-0.3.5" "$GIT_PATH/$TOR_WKT_NAME/release-0.3.5" )
RELEASE_040=( "release-0.4.0" "maint-0.4.0" "$GIT_PATH/$TOR_WKT_NAME/release-0.4.0" )
RELEASE_041=( "release-0.4.1" "maint-0.4.1" "$GIT_PATH/$TOR_WKT_NAME/release-0.4.1" )

# The master branch path has to be the main repository thus contains the
# origin that will be used to fetch the updates. All the worktrees are created
# from that repository.
ORIGIN_PATH="$GIT_PATH/$TOR_MASTER_NAME"

# SC2034 -- shellcheck thinks that these are unused.  We know better.
ACTUALLY_THESE_ARE_USED=<<EOF
${MAINT_035[0]}
${MAINT_040[0]}
${MAINT_041[0]}
${MAINT_MASTER[0]}
${RELEASE_029[0]}
${RELEASE_035[0]}
${RELEASE_040[0]}
${RELEASE_041[0]}
EOF

##########################
# Git Worktree to manage #
##########################

# List of all worktrees to work on. All defined above. Ordering is important.
# Always the maint-* branch BEFORE then the release-*.
WORKTREE=(
  RELEASE_029[@]

  MAINT_035[@]
  RELEASE_035[@]

  MAINT_040[@]
  RELEASE_040[@]

  MAINT_041[@]
  RELEASE_041[@]

  MAINT_MASTER[@]
)
COUNT=${#WORKTREE[@]}

# Controlled by the -n option. The dry run option will just output the command
# that would have been executed for each worktree.
DRY_RUN=0

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

# Merge the given branch name ($2) into the current branch ($1).
function merge_branch
{
  local cmd="git merge --no-edit $1"
  printf "  %s Merging branch %s into %s..." "$MARKER" "$1" "$2"
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Pull the given branch name.
function merge_branch_origin
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

while getopts "n" opt; do
  case "$opt" in
    n) DRY_RUN=1
       echo "    *** DRY DRUN MODE ***"
       ;;
    *)
       ;;
  esac
done

# First, fetch the origin.
goto_repo "$ORIGIN_PATH"
fetch_origin

# Go over all configured worktree.
for ((i=0; i<COUNT; i++)); do
  current=${!WORKTREE[$i]:0:1}
  previous=${!WORKTREE[$i]:1:1}
  repo_path=${!WORKTREE[$i]:2:1}

  printf "%s Handling branch \\n" "$MARKER" "${BYEL}$current${CNRM}"

  # Go into the worktree to start merging.
  goto_repo "$repo_path"
  # Checkout the current branch
  switch_branch "$current"
  # Update the current branch with an origin merge to get the latest.
  merge_branch_origin "$current"
  # Merge the previous branch. Ex: merge maint-0.2.5 into maint-0.2.9.
  merge_branch "$previous" "$current"
done
