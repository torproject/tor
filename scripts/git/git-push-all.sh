#!/usr/bin/env bash

# Usage: git-push-all.sh -t <test-branch-prefix> -r <remote-name> -s
#                        -- <git-opts>
#        arguments:
#          -t: test branch mode: Push test branches, rather than maint and
#              release branches. Pushes the branches called prefix_029,
#              prefix_035, ... , prefix_master.
#          -r: push to remote-name, rather than $TOR_UPSTREAM_REMOTE_NAME.
#          -s: push branches whose tips match upstream maint, release, or
#              master branches. The default is to skip these branches. Use
#              -s when testing for CI environment failures with old code.
#          --: pass any other arguments to git, rather than the script.
#        env vars:
#          TOR_GIT_PUSH: the git push command and arguments
#          TOR_UPSTREAM_REMOTE_NAME: the default upstream, overridden by -r
#          TOR_PUSH_DELAY: pushes the master and maint branches separately,
#                          so that CI runs in a sensible order.
#          TOR_PUSH_SAME: push branches whose tips match upstream maint,
#                         release, or master branches. Inverted by -s.
#          See the Configuration section for env var default values.
#        git-opts:
#          --no-atomic --dry-run (and any other git push option)

set -e

#################
# Configuration #
#################

# Don't change this configuration - set the env vars in your .profile
#
# The tor master git repository directory from which all the worktree have
# been created.
TOR_MASTER_NAME=${TOR_MASTER_NAME:-"tor"}
# Which directory do we push from?
if [ "$TOR_FULL_GIT_PATH" ]; then
  TOR_GIT_PUSH_PATH=${TOR_GIT_PUSH_PATH:-"$TOR_FULL_GIT_PATH/$TOR_MASTER_NAME"}
fi
# git push command and default arguments
GIT_PUSH=${TOR_GIT_PUSH:-"git push --atomic"}
# The upstream remote which git.torproject.org/tor.git points to.
DEFAULT_UPSTREAM_REMOTE=${TOR_UPSTREAM_REMOTE_NAME:-"upstream"}
# Push to a different upstream remote using -r <remote-name>
UPSTREAM_REMOTE=${DEFAULT_UPSTREAM_REMOTE}
# Add a delay between pushes, so CI runs on the most important branches first
PUSH_DELAY=${TOR_PUSH_DELAY:-0}
# Push (1) or skip (0) test branches that are the same as an upstream
# maint/master branch. Push if you are testing that the CI environment still
# works on old code, skip if you are testing new code in the branch.
# Default: skip unchanged branches.
# Inverted by the -s option.
PUSH_SAME=${TOR_PUSH_SAME:-0}

#######################
# Argument processing #
#######################

# Controlled by the -t <test-branch-prefix> option. The test branch base
# name option makes git-merge-forward.sh create new test branches:
# <tbbn>_029, <tbbn>_035, ... , <tbbn>_master, and merge forward.
TEST_BRANCH_PREFIX=

while getopts ":r:st:" opt; do
  case "$opt" in
    r) UPSTREAM_REMOTE="$OPTARG"
       echo "    *** PUSHING TO REMOTE: ${UPSTREAM_REMOTE} ***"
       shift
       shift
       OPTIND=$((OPTIND - 2))
       ;;
    s) PUSH_SAME=$((! PUSH_SAME))
       if [ "$PUSH_SAME" -eq 0 ]; then
         echo "    *** SKIPPING UNCHANGED TEST BRANCHES ***"
       else
         echo "    *** PUSHING UNCHANGED TEST BRANCHES ***"
       fi
       shift
       OPTIND=$((OPTIND - 1))
       ;;
    t) TEST_BRANCH_PREFIX="$OPTARG"
       echo "    *** PUSHING TEST BRANCHES: ${TEST_BRANCH_PREFIX}_nnn ***"
       shift
       shift
       OPTIND=$((OPTIND - 2))
       ;;
    *)
       # Assume we're done with script arguments,
       # and git push will handle the option
       break
       ;;
  esac
done

# getopts doesn't allow "-" as an option character,
# so we have to handle -- manually
if [ "$1" = "--" ]; then
  shift
fi

if [ "$TEST_BRANCH_PREFIX" ]; then
  if [ "$UPSTREAM_REMOTE" = "$DEFAULT_UPSTREAM_REMOTE" ]; then
    echo "Pushing test branches ${TEST_BRANCH_PREFIX}_nnn to " \
      "the default remote $DEFAULT_UPSTREAM_REMOTE is not allowed."
    echo "Usage: $0 -r <remote-name> -t <test-branch-prefix> <git-opts>"
    exit 1
  fi
fi

if [ "$TOR_GIT_PUSH_PATH" ]; then
  echo "Changing to $GIT_PUSH_PATH before pushing"
  cd "$TOR_GIT_PUSH_PATH"
else
  echo "Pushing from the current directory"
fi

echo "Calling $GIT_PUSH" "$@" "<branches>"

################################
# Git upstream remote branches #
################################

DEFAULT_UPSTREAM_BRANCHES=
if [ "$DEFAULT_UPSTREAM_REMOTE" != "$UPSTREAM_REMOTE" ]; then
  DEFAULT_UPSTREAM_BRANCHES=$(echo \
    "$DEFAULT_UPSTREAM_REMOTE"/master \
    "$DEFAULT_UPSTREAM_REMOTE"/{release,maint}-0.4.1 \
    "$DEFAULT_UPSTREAM_REMOTE"/{release,maint}-0.4.0 \
    "$DEFAULT_UPSTREAM_REMOTE"/{release,maint}-0.3.5 \
    "$DEFAULT_UPSTREAM_REMOTE"/{release,maint}-0.2.9 \
    )
fi

UPSTREAM_BRANCHES=$(echo \
  "$UPSTREAM_REMOTE"/master \
  "$UPSTREAM_REMOTE"/{release,maint}-0.4.1 \
  "$UPSTREAM_REMOTE"/{release,maint}-0.4.0 \
  "$UPSTREAM_REMOTE"/{release,maint}-0.3.5 \
  "$UPSTREAM_REMOTE"/{release,maint}-0.2.9 \
  )

########################
# Git branches to push #
########################

PUSH_BRANCHES=$(echo \
  master \
  {release,maint}-0.4.1 \
  {release,maint}-0.4.0 \
  {release,maint}-0.3.5 \
  {release,maint}-0.2.9 \
  )

if [ -z "$TEST_BRANCH_PREFIX" ]; then

  # maint/release push mode
  #
  # List of branches to push. Ordering is not important.
  PUSH_BRANCHES=$(echo \
    master \
    {release,maint}-0.4.1 \
    {release,maint}-0.4.0 \
    {release,maint}-0.3.5 \
    {release,maint}-0.2.9 \
    )
else

  # Test branch mode: merge to maint only, and create a new branch for 0.2.9
  #
  # List of branches to push. Ordering is not important.
  PUSH_BRANCHES=" \
    ${TEST_BRANCH_PREFIX}_master \
    ${TEST_BRANCH_PREFIX}_041 \
    ${TEST_BRANCH_PREFIX}_040 \
    ${TEST_BRANCH_PREFIX}_035 \
    ${TEST_BRANCH_PREFIX}_029 \
    "
fi

###############
# Entry point #
###############

# Skip the test branches that are the same as the upstream branches
if [ "$PUSH_SAME" -eq 0 ] && [ "$TEST_BRANCH_PREFIX" ]; then
  NEW_PUSH_BRANCHES=
  for b in $PUSH_BRANCHES; do
    PUSH_COMMIT=$(git rev-parse "$b")
    SKIP_UPSTREAM=
    for u in $DEFAULT_UPSTREAM_BRANCHES $UPSTREAM_BRANCHES; do
      UPSTREAM_COMMIT=$(git rev-parse "$u")
      if [ "$PUSH_COMMIT" = "$UPSTREAM_COMMIT" ]; then
        SKIP_UPSTREAM="$u"
      fi
    done
    if [ "$SKIP_UPSTREAM" ]; then
      printf "Skipping unchanged: %s remote: %s\n" \
        "$b" "$SKIP_UPSTREAM"
    else
      if [ "$NEW_PUSH_BRANCHES" ]; then
        NEW_PUSH_BRANCHES="${NEW_PUSH_BRANCHES} ${b}"
      else
        NEW_PUSH_BRANCHES="${b}"
      fi
    fi
  done
  PUSH_BRANCHES=${NEW_PUSH_BRANCHES}
fi

if [ "$PUSH_DELAY" -le 0 ]; then
  echo "Pushing $PUSH_BRANCHES"
  # We know that there are no spaces in any branch within $PUSH_BRANCHES, so
  # it is safe to use it unquoted.  (This also applies to the other shellcheck
  # exceptions below.)
  #
  # Push all the branches at the same time
  # shellcheck disable=SC2086
  $GIT_PUSH "$@" "$UPSTREAM_REMOTE" $PUSH_BRANCHES
else
  # Push the branches in optimal CI order, with a delay between each push
  PUSH_BRANCHES=$(echo "$PUSH_BRANCHES" | tr " " "\n" | sort -V)
  MASTER_BRANCH=$(echo "$PUSH_BRANCHES" | tr " " "\n" | grep master)
  if [ -z "$TEST_BRANCH_PREFIX" ]; then
    MAINT_BRANCHES=$(echo "$PUSH_BRANCHES" | tr " " "\n" | grep maint)
    RELEASE_BRANCHES=$(echo "$PUSH_BRANCHES" | tr " " "\n" | grep release | \
      tr "\n" " ")
    printf "Pushing with %ss delays, so CI runs in this order:\n%s\n%s\n%s\n" \
      "$PUSH_DELAY" "$MASTER_BRANCH" "$MAINT_BRANCHES" "$RELEASE_BRANCHES"
  else
    # Actually test branches based on maint branches
    MAINT_BRANCHES=$(echo "$PUSH_BRANCHES" | tr " " "\n" | grep -v master)
    printf "Pushing with %ss delays, so CI runs in this order:\n%s\n%s\n" \
      "$PUSH_DELAY" "$MASTER_BRANCH" "$MAINT_BRANCHES"
    # No release branches
    RELEASE_BRANCHES=
  fi
  $GIT_PUSH "$@" "$UPSTREAM_REMOTE" "$MASTER_BRANCH"
  sleep "$PUSH_DELAY"
  # shellcheck disable=SC2086
  for b in $MAINT_BRANCHES; do
    $GIT_PUSH "$@" "$UPSTREAM_REMOTE" "$b"
    sleep "$PUSH_DELAY"
  done
  if [ "$RELEASE_BRANCHES" ]; then
    # shellcheck disable=SC2086
    $GIT_PUSH "$@" "$UPSTREAM_REMOTE" $RELEASE_BRANCHES
  fi
fi
