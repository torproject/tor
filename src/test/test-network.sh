#! /bin/sh

# NOTE: Requires Chutney in $CHUTNEY_PATH.

TOR_DIR=$(pwd)/src/or
NETWORK_FLAVOUR=basic
CHUTNEY_NETWORK=networks/$NETWORK_FLAVOUR
myname=$(basename $0)

[ -d "$CHUTNEY_PATH" ] && [ -x "$CHUTNEY_PATH/chutney" ] || {
    echo "$myname: missing 'chutney' in CHUTNEY_PATH ($CHUTNEY_PATH)"
    exit 1
}
cd "$CHUTNEY_PATH"
PATH=$TOR_DIR:$PATH             # For picking up the right tor binary.
./tools/bootstrap-network.sh $NETWORK_FLAVOUR || exit 2

# Sleep some, waiting for the network to bootstrap.
# TODO: Add chutney command 'bootstrap-status' and use that instead.
BOOTSTRAP_TIME=18
echo -n "$myname: sleeping for $BOOTSTRAP_TIME seconds"
n=$BOOTSTRAP_TIME; while [ $n -gt 0 ]; do
    sleep 1; n=$(expr $n - 1); echo -n .
done; echo ""
./chutney verify $CHUTNEY_NETWORK
