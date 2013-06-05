#! /bin/sh

CHUTNEY_BASEDIR=./chutney       # FIXME
TOR_DIR=$(/bin/pwd)/src/or
NETWORK_FLAVOUR=basic
CHUTNEY_NETWORK=networks/$NETWORK_FLAVOUR
myname=$(/usr/bin/basename $0)

cd $CHUTNEY_BASEDIR || {
    echo "$myname: missing chutney dir: $CHUTNEY_BASEDIR"
    exit 1
}
PATH=$TOR_DIR:$PATH             # For picking up the right tor binary.
./tools/bootstrap-network.sh $NETWORK_FLAVOUR || exit 2

# Sleep some, waiting for the network to bootstrap.
# TODO: Add chutney command 'bootstrap-status' and use that instead.
BOOTSTRAP_TIME=18
echo -n "$myname: sleeping for $BOOTSTRAP_TIME seconds"
n=$BOOTSTRAP_TIME; while [ $n -gt 0 ]; do
    /bin/sleep 1; n=$(/usr/bin/expr $n - 1); echo -n .
done; echo ""
./chutney verify $CHUTNEY_NETWORK
