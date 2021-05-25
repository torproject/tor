#!/usr/bin/env bash

SCRIPT_NAME=$(basename "$0")

function usage()
{
  echo "$SCRIPT_NAME [-h] [-n] [-u]"
  echo
  echo "  arguments:"
  echo "   -h: show this help text"
  echo "   -n: dry run mode"
  echo "       (default: run commands)"
  echo "   -u: if a directory or worktree already exists, use it"
  echo "       (default: fail and exit on existing directories)"
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
  echo "   TOR_GIT_ORIGIN_PULL: the origin remote pull URL."
  echo "       (current: $GIT_ORIGIN_PULL)"
  echo "   TOR_GIT_ORIGIN_PUSH: the origin remote push URL"
  echo "       (current: $GIT_ORIGIN_PUSH)"
  echo "   TOR_UPSTREAM_REMOTE_NAME: the default upstream remote."
  echo "       If \$TOR_UPSTREAM_REMOTE_NAME is not 'origin', we have a"
  echo "       separate upstream remote, and we don't push to origin."
  echo "       (default: $DEFAULT_UPSTREAM_REMOTE)"
  echo "   TOR_GITHUB_PULL: the tor-github remote pull URL"
  echo "       (current: $GITHUB_PULL)"
  echo "   TOR_GITHUB_PUSH: the tor-github remote push URL"
  echo "       (current: $GITHUB_PUSH)"
  echo "   TOR_GITLAB_PULL: the tor-gitlab remote pull URL"
  echo "       (current: $GITLAB_PULL)"
  echo "   TOR_GITLAB_PUSH: the tor-gitlab remote push URL"
  echo "       (current: $GITLAB_PUSH)"
  echo "   TOR_EXTRA_CLONE_ARGS: extra arguments to git clone"
  echo "       (current: $TOR_EXTRA_CLONE_ARGS)"
  echo "   TOR_EXTRA_REMOTE_NAME: the name of an extra remote"
  echo "       This remote is not pulled by this script or git-pull-all.sh."
  echo "       This remote is not pushed by git-push-all.sh."
  echo "       (current: $TOR_EXTRA_REMOTE_NAME)"
  echo "   TOR_EXTRA_REMOTE_PULL: the extra remote pull URL."
  echo "       (current: $TOR_EXTRA_REMOTE_PULL)"
  echo "   TOR_EXTRA_REMOTE_PUSH: the extra remote push URL"
  echo "       (current: $TOR_EXTRA_REMOTE_PUSH)"
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

# Origin repositories
GIT_ORIGIN_PULL=${TOR_GIT_ORIGIN_PULL:-"https://git.torproject.org/tor.git"}
GIT_ORIGIN_PUSH=${TOR_GIT_ORIGIN_PUSH:-"git@git-rw.torproject.org:tor.git"}
# The upstream remote which git.torproject.org/tor.git points to.
DEFAULT_UPSTREAM_REMOTE=${TOR_UPSTREAM_REMOTE_NAME:-"upstream"}
# Copy the URLs from origin
GIT_UPSTREAM_PULL="$GIT_ORIGIN_PULL"
GIT_UPSTREAM_PUSH="$GIT_ORIGIN_PUSH"
# And avoid pushing to origin if we have an upstream
if [ "$DEFAULT_UPSTREAM_REMOTE" != "origin" ]; then
  GIT_ORIGIN_PUSH="No pushes to origin, if there is an upstream"
fi
# GitHub repositories
GITHUB_PULL=${TOR_GITHUB_PULL:-"https://github.com/torproject/tor.git"}
GITHUB_PUSH=${TOR_GITHUB_PUSH:-"No_Pushing_To_GitHub"}

# GitLab repositories
GITLAB_PULL=${TOR_GITLAB_PULL:-"https://gitlab.torproject.org/tpo/core/tor.git"}
GITLAB_PUSH=${TOR_GITLAB_PUSH:-"No_Pushing_To_GitLab"}

##########################
# Git branches to manage #
##########################

# The branches and worktrees need to be modified when there is a new branch,
# and when an old branch is no longer supported.

set -e
eval "$(git-list-tor-branches.sh -b)"
set +e

# The main branch path has to be the main repository thus contains the
# origin that will be used to fetch the updates. All the worktrees are created
# from that repository.
ORIGIN_PATH="$GIT_PATH/$TOR_MASTER_NAME"

#######################
# Argument processing #
#######################

# Controlled by the -n option. The dry run option will just output the command
# that would have been executed for each worktree.
DRY_RUN=0

# Controlled by the -s option. The use existing option checks for existing
# directories, and re-uses them, rather than creating a new directory.
USE_EXISTING=0
USE_EXISTING_HINT="Use existing: '$SCRIPT_NAME -u'."

while getopts "hnu" opt; do
  case "$opt" in
    h) usage
       exit 0
       ;;
    n) DRY_RUN=1
       echo "    *** DRY RUN MODE ***"
       ;;
    u) USE_EXISTING=1
       echo "    *** USE EXISTING DIRECTORIES MODE ***"
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
SKIPPED="${BYEL}skipped${CNRM}"
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
    printf "      %s\\n" "$2"
    exit 1
  fi
}

# Validate the given returned value (error code), print success, skipped, or
# failed. If $USE_EXISTING is 0, fail on error, otherwise, skip on error.
# The second argument is the error output in case of failure, it is printed
# out. On failure, this function exits.
function validate_ret_skip
{
  if [ "$1" -ne 0 ]; then
    if [ "$USE_EXISTING" -eq "0" ]; then
      # Fail and exit with error
      validate_ret "$1" "$2 $USE_EXISTING_HINT"
    else
      printf "%s\\n" "$SKIPPED"
      printf "      %s\\n" "${IWTH}$2${CNRM}"
      # Tell the caller to skip the rest of the function
      return 0
    fi
  fi
  # Tell the caller to continue
  return 1
}

# Create a directory, and any missing enclosing directories.
# If the directory already exists: fail if $USE_EXISTING is 0, otherwise skip.
function make_directory
{
  local cmd="mkdir -p '$1'"
  printf "  %s Creating directory %s..." "$MARKER" "$1"
  local check_cmd="[ ! -d '$1' ]"
  msg=$( eval "$check_cmd" 2>&1 )
  if validate_ret_skip $? "Directory already exists."; then
    return
  fi
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Create a symlink from the first argument to the second argument
# If the link already exists: fail if $USE_EXISTING is 0, otherwise skip.
function make_symlink
{
  local cmd="ln -s '$1' '$2'"
  printf "  %s Creating symlink from %s to %s..." "$MARKER" "$1" "$2"
  local check_cmd="[ ! -e '$2' ]"
  msg=$( eval "$check_cmd" 2>&1 )
  if validate_ret_skip $? "File already exists."; then
    return
  fi
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Go into the directory or repository, even if $DRY_RUN is non-zero.
# If the directory does not exist, fail and log an error.
# Otherwise, silently succeed.
function goto_dir
{
  if ! cd "$1" 1>/dev/null 2>/dev/null ; then
    printf "  %s Changing to directory %s..." "$MARKER" "$1"
    validate_ret 1 "$1: Not found. Stopping."
  fi
}

# Clone a repository into a directory.
# If the directory already exists: fail if $USE_EXISTING is 0, otherwise skip.
function clone_repo
{
  local cmd="git clone $TOR_EXTRA_CLONE_ARGS '$1' '$2'"
  printf "  %s Cloning %s into %s..." "$MARKER" "$1" "$2"
  local check_cmd="[ ! -d '$2' ]"
  msg=$( eval "$check_cmd" 2>&1 )
  if validate_ret_skip $? "Directory already exists."; then
    # If we skip the clone, we need to do a fetch
    goto_dir "$ORIGIN_PATH"
    fetch_remote "origin"
    return
  fi
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Add a remote by name and URL.
# If the remote already exists: fail if $USE_EXISTING is 0, otherwise skip.
function add_remote
{
  local cmd="git remote add '$1' '$2'"
  printf "  %s Adding remote %s at %s..." "$MARKER" "$1" "$2"
  local check_cmd="git remote get-url '$1'"
  msg=$( eval "$check_cmd" 2>&1 )
  ret=$?
  # We don't want a remote, so we invert the exit status
  if validate_ret_skip $(( ! ret )) \
                       "Remote already exists for $1 at $msg."; then
    return
  fi
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Set a remote's push URL by name and URL.
function set_remote_push
{
  local cmd="git remote set-url --push '$1' '$2'"
  printf "  %s Setting remote %s push URL to '%s'..." "$MARKER" "$1" "$2"
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Fetch a remote by name.
function fetch_remote
{
  local cmd="git fetch '$1'"
  printf "  %s Fetching %s..." "$MARKER" "$1"
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Replace the fetch configs for a remote with config if they match a pattern.
function replace_fetch_config
{
  local cmd="git config --replace-all remote.'$1'.fetch '$2' '$3'"
  printf "  %s Replacing %s fetch configs for '%s'..." \
    "$MARKER" "$1" "$3"
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Set up the tor-github PR config, so tor-github/pr/NNNN/head points to GitHub
# PR NNNN. In some repositories, "/head" is optional.
function set_tor_github_pr_fetch_config
{
  # Standard branches
  replace_fetch_config tor-github \
    "+refs/heads/*:refs/remotes/tor-github/*" \
    "refs/heads"
  # PRs
  replace_fetch_config "tor-github" \
    "+refs/pull/*:refs/remotes/tor-github/pr/*" \
    "refs/pull.*pr"
}

# Set up the tor-github PR config, so tor-gitlab/mr/NNNN points to GitHub
# MR NNNN. In some repositories, "/head" is optional.
function set_tor_gitlab_mr_fetch_config
{
  # standard branches
  replace_fetch_config tor-gitlab \
    "+refs/heads/*:refs/remotes/tor-gitlab/*" \
    "refs/heads"
  # MRs
  replace_fetch_config tor-gitlab \
    "+refs/merge-requests/*/head:refs/remotes/tor-gitlab/mr/*" \
    "refs/merge-requests.*mr"
}

# Add a new worktree for branch at path.
# If the directory already exists: fail if $USE_EXISTING is 0, otherwise skip.
function add_worktree
{
  local cmd="git worktree add '$2' '$1'"
  printf "  %s Adding worktree for %s at %s..." "$MARKER" "$1" "$2"
  local check_cmd="[ ! -d '$2' ]"
  msg=$( eval "$check_cmd" 2>&1 )
  if validate_ret_skip $? "Directory already exists."; then
    return
  fi
  if [ $DRY_RUN -eq 0 ]; then
    msg=$( eval "$cmd" 2>&1 )
    validate_ret $? "$msg"
  else
    printf "\\n      %s\\n" "${IWTH}$cmd${CNRM}"
  fi
}

# Switch to the given branch name.
# If the branch does not exist: fail.
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
# If the branch already exists: fail if $USE_EXISTING is 0, otherwise skip.
function new_branch
{
  local cmd="git checkout -b '$1'"
  printf "  %s Creating new branch %s..." "$MARKER" "$1"
  local check_cmd="git branch --list '$1'"
  msg=$( eval "$check_cmd" 2>&1 )
  if validate_ret_skip $? "Branch already exists."; then
    return
  fi
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

# Set the upstream for branch to upstream.
function set_upstream
{
  # Note the argument order is swapped
  local cmd="git branch --set-upstream-to='$2' '$1'"
  printf "  %s Setting upstream for %s to %s..." "$MARKER" "$1" "$2"
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

printf "%s Setting up the repository and remote %s\\n" "$MARKER" \
  "${BYEL}origin${CNRM}"
# First, fetch the origin.
ORIGIN_PARENT=$(dirname "$ORIGIN_PATH")
make_directory "$ORIGIN_PARENT"
# This is just cd with an error check
goto_dir "$ORIGIN_PARENT"

# clone repository / origin remote
clone_repo "$GIT_ORIGIN_PULL" "$TOR_MASTER_NAME"
goto_dir "$ORIGIN_PATH"
set_remote_push "origin" "$GIT_ORIGIN_PUSH"

# upstream remote, if different to origin
if [ "$DEFAULT_UPSTREAM_REMOTE" != "origin" ]; then
  printf "%s Setting up remote %s\\n" "$MARKER" \
    "${BYEL}$DEFAULT_UPSTREAM_REMOTE${CNRM}"
  add_remote "$DEFAULT_UPSTREAM_REMOTE" "$GIT_UPSTREAM_PULL"
  set_remote_push "$DEFAULT_UPSTREAM_REMOTE" "$GIT_UPSTREAM_PUSH"
  fetch_remote "$DEFAULT_UPSTREAM_REMOTE"
fi

# GitHub remote
printf "%s Setting up remote %s\\n" "$MARKER" "${BYEL}tor-github${CNRM}"
# Add remote
add_remote "tor-github" "$GITHUB_PULL"
set_remote_push "tor-github" "$GITHUB_PUSH"
# Add custom fetch for PRs
set_tor_github_pr_fetch_config
# Now fetch them all
fetch_remote "tor-github"

# GitLab remote
printf "%s Setting up remote %s\\n" "$MARKER" "${BYEL}tor-gitlab${CNRM}"
add_remote "tor-gitlab" "$GITLAB_PULL"
set_remote_push "tor-gitlab" "$GITLAB_PUSH"
# Add custom fetch for MRs
set_tor_gitlab_mr_fetch_config
# Now fetch them all
fetch_remote "tor-gitlab"

# Extra remote
if [ "$TOR_EXTRA_REMOTE_NAME" ]; then
  printf "%s Setting up remote %s\\n" "$MARKER" \
    "${BYEL}$TOR_EXTRA_REMOTE_NAME${CNRM}"
  # Add remote
  add_remote "$TOR_EXTRA_REMOTE_NAME" "$TOR_EXTRA_REMOTE_PULL"
  set_remote_push "$TOR_EXTRA_REMOTE_NAME" "$TOR_EXTRA_REMOTE_PUSH"
  # But leave it to the user to decide if they want to fetch it
  #fetch_remote "$TOR_EXTRA_REMOTE_NAME"
fi

# Go over all configured worktree.
for ((i=0; i<COUNT; i++)); do
  branch=${!WORKTREE[$i]:0:1}
  repo_path=${!WORKTREE[$i]:1:1}

  printf "%s Handling branch %s\\n" "$MARKER" "${BYEL}$branch${CNRM}"
  # We cloned the repository, and main is the default branch
  if [ "$branch" = "main" ]; then
    if [ "$TOR_MASTER_NAME" != "main" ]; then
      # Set up a main branch link in the worktree directory
      make_symlink "$repo_path" "$GIT_PATH/$TOR_WKT_NAME/main"
    fi
  else
    # git makes worktree directories if they don't exist
    add_worktree "origin/$branch" "$repo_path"
  fi
  goto_dir "$repo_path"
  switch_or_new_branch "$branch"
  set_upstream "$branch" "origin/$branch"
done

echo
echo "Remember to copy the git hooks from tor/scripts/git/*.git-hook to"
echo "$ORIGIN_PATH/.git/hooks/*"
