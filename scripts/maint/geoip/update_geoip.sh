#!/bin/sh

set -e

DIR=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)

location --quiet update
location dump "$TMP/geoip-dump.txt"

OLDDIR=$(pwd)
cd "$DIR/geoip-db-tool/"
cargo build --release
cd "$OLDDIR"

"$DIR/geoip-db-tool/target/release/geoip-db-tool" -i "$TMP/geoip-dump.txt"
