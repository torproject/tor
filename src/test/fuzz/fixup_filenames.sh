#!/bin/sh

set -e

if [ ! -d "$1" ] ; then
    echo "I need a directory"
    exit 1
fi

for fn in "$1"/* ; do
    prev=`basename "$fn"`
    post=`sha256sum "$fn" | sed -e 's/ .*//;'`
    if [ "$prev" == "$post" ] ; then
      echo "OK $prev"
    else
      echo "mv $prev $post"
      mv "$fn" "$1/$post"
    fi
done
