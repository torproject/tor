#!/bin/sh

if test "x$TRUNNEL_PATH" != "x"; then
  PYTHONPATH="${TRUNNEL_PATH}:${PYTHONPATH}"
  export PYTHONPATH
fi

python -m trunnel --require-version=1.2 ./src/trunnel/*.trunnel

python -m trunnel --require-version=1.2 --write-c-files --target-dir=./src/ext/trunnel/

