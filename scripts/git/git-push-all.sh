#!/usr/bin/env bash

SCRIPT_NAME=$(basename "$0")

function usage()
{
  if [ "$TOR_PUSH_SAME" ]; then
    CURRENT_PUSH_SAME="push"
  else
    CURRENT_PUSH_SAME="skip"
  fi

  echo "$SCRIPT_NAME [-h] [-r <remote-name> [-t <test-branch-prefix>]] [-s]"
  # The next line looks misaligned, but it lines up in the output
  echo "                [-- [-n] [--no-atomic] <git push options>]"
  echo
  echo "  arguments:"
  echo "   -h: show this help text"
  echo "   -n: dry run mode"
  echo "       (default: run commands)"
  echo "   -r: push to remote-name, rather than the default upstream remote."
  echo "       (default: $DEFAULT_UPSTREAM_REMOTE, current: $UPSTREAM_REMOTE)"
  echo "   -t: test branch mode: push test branches to remote-name. Pushes"
  echo "       branches prefix_035, prefix_040,  ... , prefix_main."
  echo "       (default: push maint-*, release-*, and main)"
  echo "   -s: push branches whose tips match upstream maint, release, or"
  echo "       main branches. The default is to skip these branches,"
  echo "       because they do not contain any new code. Use -s to test for"
  echo "       CI environment failures, using code that previously passed CI."
  echo "       (default: skip; current: $CURRENT_PUSH_SAME matching branches)"
  echo "   --: pass further arguments to git push."
  echo "       All unrecognised arguments are passed to git push, but complex"
  echo "       arguments before -- may be mangled by getopt."
  echo "       (default: git push --atomic, current: $GIT_PUSH)"
  echo
  echo " env vars:"
  echo "   optional:"
  echo "   TOR_GIT_PUSH_PATH: change to this directory before pushing."
  echo "       (default: if \$TOR_FULL_GIT_PATH is set,"
  echo "       use \$TOR_FULL_GIT_PATH/\$TOR_MASTER;"
  echo "       Otherwise, use the current directory for pushes;"
  echo "       current: $TOR_GIT_PUSH_PATH)"
  echo "   TOR_FULL_GIT_PATH: where the git repository directories reside."
  echo "       We recommend using \$HOME/git/."
  echo "       (default: use the current directory for pushes;"
  echo "       current: $TOR_FULL_GIT_PATH)"
  echo "   TOR_MASTER: the name of the directory containing the tor.git clone"
  echo "       The primary tor git directory is \$GIT_PATH/\$TOR_MASTER"
  echo "       (default: tor; current: $TOR_MASTER_NAME)"
  echo
  echo "   TOR_UPSTREAM_REMOTE_NAME: the default upstream remote."
  echo "       Overridden by -r."
  echo "       (default: upstream; current: $UPSTREAM_REMOTE)"
  echo "   TOR_GIT_PUSH: the git push command and default arguments."
  echo "       Overridden by <git push options> after --."
  echo "       (default: git push --atomic; current: $GIT_PUSH)"
  echo "   TOR_PUSH_SAME: push branches whose tips match upstream maint,"
  echo "       release, or main branches. Inverted by -s."
  echo "       (default: skip; current: $CURRENT_PUSH_SAME matching branches)"
  echo "   TOR_PUSH_DELAY: pushes the main and maint branches separately,"
  echo "       so that CI runs in a sensible order."
  echo "       (default: push all branches immediately; current: $PUSH_DELAY)"
  echo "   we recommend that you set these env vars in your ~/.profile"
}

set -e

#################
# Configuration #
#################

# Don't change this configuration - set the env vars in your .profile
#
# The primary tor git repository directory from which all the worktree have
# been created.
TOR_MASTER_NAME=${TOR_MASTER_NAME:-"tor"}
# Which directory do we push from?
if [ "$TOR_FULL_GIT_PATH" ]; then
  TOR_GIT_PUSH_PATH=${TOR_GIT_PUSH_PATH:-"$TOR_FULL_GIT_PATH/$TOR_MASTER_NAME"}
fi
# git push command and default arguments
GIT_PUSH=${TOR_GIT_PUSH:-"git push --atomic"}
# The upstream remote which gitlab.torproject.org/tpo/core/tor.git points to.
DEFAULT_UPSTREAM_REMOTE=${TOR_UPSTREAM_REMOTE_NAME:-"upstream"}
# Push to a different upstream remote using -r <remote-name>
UPSTREAM_REMOTE=${DEFAULT_UPSTREAM_REMOTE}
# Add a delay between pushes, so CI runs on the most important branches first
PUSH_DELAY=${TOR_PUSH_DELAY:-0}
# Push (1) or skip (0) test branches that are the same as an upstream
# maint/main branch. Push if you are testing that the CI environment still
# works on old code, skip if you are testing new code in the branch.
# Default: skip unchanged branches.
# Inverted by the -s option.
PUSH_SAME=${TOR_PUSH_SAME:-0}

#######################
# Argument processing #
#######################

# Controlled by the -t <test-branch-prefix> option. The test branch prefix
# option makes git-merge-forward.sh create new test branches:
# <tbp>_035, <tbp>_040, ... , <tbp>_main, and merge each branch forward into
# the next one.
TEST_BRANCH_PREFIX=

while getopts ":hr:st:" opt; do
  case "$opt" in
    h) usage
       exit 0
       ;;
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
       # Make git push handle the option
       # This might mangle options with spaces, use -- for complex options
       GIT_PUSH="$GIT_PUSH $1"
       shift
       OPTIND=$((OPTIND - 1))
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
    echo
    usage
    exit 1
  fi
fi

if [ "$TOR_GIT_PUSH_PATH" ]; then
  echo "Changing to $TOR_GIT_PUSH_PATH before pushing"
  cd "$TOR_GIT_PUSH_PATH"
else
  echo "Pushing from the current directory"
fi

echo "Calling $GIT_PUSH" "$@" "<branches>"

################################
# Git upstream remote branches #
################################

set -e
DEFAULT_UPSTREAM_BRANCHES=
if [ "$DEFAULT_UPSTREAM_REMOTE" != "$UPSTREAM_REMOTE" ]; then
    for br in $(git-list-tor-branches.sh -l); do
        DEFAULT_UPSTREAM_BRANCHES="${DEFAULT_UPSTREAM_BRANCHES} ${DEFAULT_UPSTREAM_REMOTE}/${br}"
    done
fi

UPSTREAM_BRANCHES=
for br in $(git-list-tor-branches.sh -l); do
    UPSTREAM_BRANCHES="${UPSTREAM_BRANCHES} ${UPSTREAM_REMOTE}/${br}"
done

########################
# Git branches to push #
########################

if [ -z "$TEST_BRANCH_PREFIX" ]; then

  # maint/release push mode: push all branches.
  #
  # List of branches to push. Ordering is not important.
  PUSH_BRANCHES="$(git-list-tor-branches.sh -l)"
else

  # Test branch push mode: push test branches, based on each maint branch.
  #
  # List of branches to push. Ordering is not important.
  PUSH_BRANCHES=""
  for suffix in $(git-list-tor-branches.sh -s -R); do
      PUSH_BRANCHES="${PUSH_BRANCHES} ${TEST_BRANCH_PREFIX}${suffix}"
  done
fi

set +e

###############
# Entry point #
###############

if [ "$TEST_BRANCH_PREFIX" ]; then
  # Skip the test branches that are the same as the default or current
  # upstream branches (they have already been tested)
  UPSTREAM_SKIP_SAME_AS="$UPSTREAM_BRANCHES $DEFAULT_UPSTREAM_BRANCHES"
else
  # Skip the local maint-*, release-*, main branches that are the same as the
  # current upstream branches, but ignore the default upstream
  # (we want to update a non-default remote, even if it matches the default)
  UPSTREAM_SKIP_SAME_AS="$UPSTREAM_BRANCHES"
fi

# Skip branches that match the relevant upstream(s)
if [ "$PUSH_SAME" -eq 0 ]; then
  NEW_PUSH_BRANCHES=
  for b in $PUSH_BRANCHES; do
    PUSH_COMMIT=$(git rev-parse "$b")
    SKIP_UPSTREAM=
    for u in $UPSTREAM_SKIP_SAME_AS; do
      # Skip the branch check on error
      UPSTREAM_COMMIT=$(git rev-parse "$u" 2>/dev/null) || continue
      if [ "$PUSH_COMMIT" = "$UPSTREAM_COMMIT" ]; then
        SKIP_UPSTREAM="$u"
      fi
    done
    if [ "$SKIP_UPSTREAM" ]; then
      printf "Skipping unchanged: %s matching remote: %s\\n" \
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

if [ ! "$PUSH_BRANCHES" ]; then
  echo "No branches to push!"
  # We expect the rest of the script to run without errors, even if there
  # are no branches
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
  PUSH_BRANCHES=$(echo "$PUSH_BRANCHES" | tr " " "\\n" | sort -V)
  MASTER_BRANCH=$(echo "$PUSH_BRANCHES" | tr " " "\\n" | grep main$) \
      || true # Skipped main branch
  if [ -z "$TEST_BRANCH_PREFIX" ]; then
    MAINT_BRANCHES=$(echo "$PUSH_BRANCHES" | tr " " "\\n" | grep maint) \
        || true # Skipped all maint branches
    RELEASE_BRANCHES=$(echo "$PUSH_BRANCHES" | tr " " "\\n" | grep release | \
      tr "\\n" " ") || true # Skipped all release branches
  else
    # Actually test branches based on maint branches
    MAINT_BRANCHES=$(echo "$PUSH_BRANCHES" | tr " " "\\n" | grep -v main$) \
        || true # Skipped all maint test branches
    # No release branches
    RELEASE_BRANCHES=
  fi
  if [ "$MASTER_BRANCH" ] || [ "$MAINT_BRANCHES" ] \
      || [ "$RELEASE_BRANCHES" ]; then
    printf "Pushing with %ss delays, so CI runs in this order:\\n" \
           "$PUSH_DELAY"
    if [ "$MASTER_BRANCH" ]; then
      printf "%s\\n" "$MASTER_BRANCH"
    fi
    if [ "$MAINT_BRANCHES" ]; then
      printf "%s\\n" "$MAINT_BRANCHES"
    fi
    if [ "$RELEASE_BRANCHES" ]; then
      printf "%s\\n" "$RELEASE_BRANCHES"
    fi
  fi
  # shellcheck disable=SC2086
  for b in $MASTER_BRANCH $MAINT_BRANCHES; do
    $GIT_PUSH "$@" "$UPSTREAM_REMOTE" "$b"
    # If we are pushing more than one branch, delay.  In the unlikely scenario
    # where we are pushing maint branches without the main branch, or maint
    # without release, there may be an extra delay
    if [ "$MAINT_BRANCHES" ] || [ "$RELEASE_BRANCHES" ]; then
      sleep "$PUSH_DELAY"
    fi
  done
  if [ "$RELEASE_BRANCHES" ]; then
    # shellcheck disable=SC2086
    $GIT_PUSH "$@" "$UPSTREAM_REMOTE" $RELEASE_BRANCHES
  fi
fi
