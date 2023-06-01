#!/bin/sh

set -e

DIR=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)

DB_PATH="/var/lib/location/database.db"

# In case it exists as a dead symlink.
if [ -e "$DB_PATH" ]; then
    unlink "$DB_PATH"
fi

curl -o "$DB_PATH.xz" "https://location.ipfire.org/databases/1/location.db.xz"
xz -d "$DB_PATH.xz"
location dump "$TMP/geoip-dump.txt"

OLDDIR=$(pwd)
cd "$DIR/geoip-db-tool/"
cargo build --release
cd "$OLDDIR"

"$DIR/geoip-db-tool/target/release/geoip-db-tool" -i "$TMP/geoip-dump.txt"
