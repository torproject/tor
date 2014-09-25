#!/bin/sh

if test "x$TRUNNEL_PATH" != "x"; then
  PYTHONPATH="${TRUNNEL_PATH}:${PYTHONPATH}"
  export PYTHONPATH
fi

python -m trunnel ./src/trunnel/*.trunnel

python -m trunnel --write-c-files --target-dir=./src/ext/trunnel/

