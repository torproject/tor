#!/bin/sh

set -e

CMDDIR=$(cd "$(dirname "$0")" && pwd)

if [ ! -e "./src/config/geoip" ] ; then
    echo "Run this from inside the root dir of your oldest LTS repository"
    exit 1
fi

if [ -n "$(git status --untracked-files=no --porcelain)" ]; then
    echo "Working directory is not clean."
    exit 1
fi

TOPDIR=$(pwd)
cd "./src/config/"
"${CMDDIR}/update_geoip.sh"
cd "${TOPDIR}"

DASH_DATE=$(date -u +"%Y-%m-%d")
SLASH_DATE=$(date -u +"%Y/%m/%d")
CHANGESFILE="changes/geoip-$DASH_DATE"

cat > "$CHANGESFILE" <<EOF
  o Minor features (geoip data):
    - Update the geoip files to match the IPFire Location Database,
      as retrieved on ${SLASH_DATE}.
EOF

git add "$CHANGESFILE"

git commit -a -m "Update geoip files to match ipfire location db, $SLASH_DATE."
