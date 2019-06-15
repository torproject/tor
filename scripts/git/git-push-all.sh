#!/usr/bin/env bash

# The remote upstream branch on which git.torproject.org/tor.git points to.
UPSTREAM_BRANCH=${TOR_UPSTREAM_REMOTE_NAME:-"upstream"}

git push "$UPSTREAM_BRANCH" \
   master \
   {release,maint}-0.4.1 \
   {release,maint}-0.4.0 \
   {release,maint}-0.3.5 \
   {release,maint}-0.2.9
