#! /bin/sh

ECHO_N="/bin/echo -n"

until [ -z $1 ]
do
  case $1 in
    --chutney-path)
      export CHUTNEY_PATH="$2"
      shift
    ;;
    --tor-path)
      export TOR_DIR="$2"
      shift
    ;;
    --flavo?r|--network-flavo?r)
      export NETWORK_FLAVOUR="$2"
      shift
    ;;
    *)
      echo "Sorry, I don't know what to do with '$1'."
      exit 2
    ;;
  esac
  shift
done

TOR_DIR="${TOR_DIR:-$PWD}"
NETWORK_FLAVOUR=${NETWORK_FLAVOUR:-basic}
CHUTNEY_NETWORK=networks/$NETWORK_FLAVOUR
myname=$(basename $0)

[ -d "$CHUTNEY_PATH" ] && [ -x "$CHUTNEY_PATH/chutney" ] || {
    echo "$myname: missing 'chutney' in CHUTNEY_PATH ($CHUTNEY_PATH)"
    exit 1
}
cd "$CHUTNEY_PATH"
# For picking up the right tor binaries.
PATH="$TOR_DIR/src/or:$TOR_DIR/src/tools:$PATH"
./tools/bootstrap-network.sh $NETWORK_FLAVOUR || exit 2

# Sleep some, waiting for the network to bootstrap.
# TODO: Add chutney command 'bootstrap-status' and use that instead.
BOOTSTRAP_TIME=18
$ECHO_N "$myname: sleeping for $BOOTSTRAP_TIME seconds"
n=$BOOTSTRAP_TIME; while [ $n -gt 0 ]; do
    sleep 1; n=$(expr $n - 1); $ECHO_N .
done; echo ""
./chutney verify $CHUTNEY_NETWORK
