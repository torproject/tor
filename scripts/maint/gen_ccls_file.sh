#!/bin/sh

##############################################################################
# THIS MUST BE CALLED FROM THE ROOT DIRECTORY. IT IS USED BY THE MAKEFILE SO #
# IN THEORY, YOU SHOULD NEVER CALL THIS.                                     #
##############################################################################

set -e

CCLS_FILE=".ccls"

# Get all #define *_PRIVATE from our source. We need to list them in our .ccls
# file and enable them otherwise ccls will not find their definition thinking
# that they are dead code.
PRIVATE_DEFS=$(grep -r --include \*.h "_PRIVATE" | grep "#ifdef" | cut -d' ' -f2 | sort | uniq)

echo "clang" > "$CCLS_FILE"
for p in $PRIVATE_DEFS; do
  echo "-D$p" >> "$CCLS_FILE"
done
