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

# Add these include so the ccls server can properly check new files that are
# not in the compile_commands.json yet
{
    echo "-I."
    echo "-I./src"
    echo "-I./src/ext"
    echo "-I./src/ext/trunnel"
} >> "$CCLS_FILE"

# Add all defines (-D).
for p in $PRIVATE_DEFS; do
    echo "-D$p" >> "$CCLS_FILE"
done
