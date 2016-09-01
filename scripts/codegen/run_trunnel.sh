#!/bin/sh

if test "x$TRUNNEL_PATH" != "x"; then
  PYTHONPATH="${TRUNNEL_PATH}:${PYTHONPATH}"
  export PYTHONPATH
fi

# Get all .trunnel files recursively from that directory so we can support
# multiple sub-directories.
for file in `find ./src/trunnel/ -name '*.trunnel'`; do
  python -m trunnel --require-version=1.4 $file
done

python -m trunnel --require-version=1.4 --write-c-files --target-dir=./src/ext/trunnel/

