#!/usr/bin/env bash

# Usage: git-push-all.sh
#        env vars: TOR_UPSTREAM_REMOTE_NAME=upstream TOR_PUSH_DELAY=0
#        options: --no-atomic --dry-run (any other git push option)
#
# TOR_PUSH_DELAY pushes the master and maint branches separately, so that CI
# runs in a sensible order.
# push --atomic is the default when TOR_PUSH_DELAY=0, and for release branches.

set -e

# The upstream remote which git.torproject.org/tor.git points to.
UPSTREAM_REMOTE=${TOR_UPSTREAM_REMOTE_NAME:-"upstream"}
# Add a delay between pushes, so CI runs on the most important branches first
PUSH_DELAY=${TOR_PUSH_DELAY:-0}

PUSH_BRANCHES=$(echo \
  master \
  {release,maint}-0.4.1 \
  {release,maint}-0.4.0 \
  {release,maint}-0.3.5 \
  {release,maint}-0.2.9 \
  )

if [ "$PUSH_DELAY" -le 0 ]; then
  echo "Pushing $PUSH_BRANCHES"
  # We know that there are no spaces in any branch within $PUSH_BRANCHES, so
  # it is safe to use it unquoted.  (This also applies to the other shellcheck
  # exceptions below.)
  #
  # shellcheck disable=SC2086
  git push --atomic "$@" "$UPSTREAM_REMOTE" $PUSH_BRANCHES
else
  PUSH_BRANCHES=$(echo "$PUSH_BRANCHES" | tr " " "\n" | sort -V)
  MASTER_BRANCH=$(echo "$PUSH_BRANCHES" | tr " " "\n" | grep master)
  MAINT_BRANCHES=$(echo "$PUSH_BRANCHES" | tr " " "\n" | grep maint)
  RELEASE_BRANCHES=$(echo "$PUSH_BRANCHES" | tr " " "\n" | grep release | \
    tr "\n" " ")
  printf "Pushing with %ss delays, so CI runs in this order:\n%s\n%s\n%s\n" \
    "$PUSH_DELAY" "$MASTER_BRANCH" "$MAINT_BRANCHES" "$RELEASE_BRANCHES"
  git push "$@" "$UPSTREAM_REMOTE" "$MASTER_BRANCH"
  sleep "$PUSH_DELAY"
  # shellcheck disable=SC2086
  for b in $MAINT_BRANCHES; do
    git push "$@" "$UPSTREAM_REMOTE" $b
    sleep "$PUSH_DELAY"
  done
  # shellcheck disable=SC2086
  git push --atomic "$@" "$UPSTREAM_REMOTE" $RELEASE_BRANCHES
fi
