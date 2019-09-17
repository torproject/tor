#!/bin/sh

if test "x$TRUNNEL_PATH" != "x"; then
  PYTHONPATH="${TRUNNEL_PATH}:${PYTHONPATH}"
  export PYTHONPATH
fi

OPTIONS="--require-version=1.5.1"

# Get all .trunnel files recursively from that directory so we can support
# multiple sub-directories.
for file in `find ./src/trunnel/ -name '*.trunnel'`; do
  python -m trunnel ${OPTIONS} $file
done

python -m trunnel ${OPTIONS} --write-c-files --target-dir=./src/ext/trunnel/

