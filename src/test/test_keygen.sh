#!/bin/sh

# Note: some of this code is lifted from zero_length_keys.sh, and could be
# unified.

umask 077
set -e

if [ $# -eq 0 ] || [ ! -f ${1} ] || [ ! -x ${1} ]; then
  echo "Usage: ${0} PATH_TO_TOR [case-number]"
  exit 1
elif [ $# -ge 1 ]; then
  TOR_BINARY="${1}"
  shift

  if [ $# -ge 1 ]; then
      dflt=0
  else
      dflt=1
  fi

  CASE2A=$dflt
  CASE2B=$dflt
  CASE3A=$dflt
  CASE3B=$dflt
  CASE3C=$dflt
  CASE4=$dflt
  CASE5=$dflt
  CASE6=$dflt
  CASE7=$dflt
  CASE8=$dflt
  CASE9=$dflt
  CASE10=$dflt

  if [ $# -ge 1 ]; then
     eval "CASE${1}"=1
  fi
fi

die() { echo "$1" >&2 ; exit 5; }
check_dir() { [ -d "$1" ] || die "$1 did not exist"; }
check_file() { [ -e "$1" ] || die "$1 did not exist"; }
check_no_file() { [ -e "$1" ] && die "$1 was not supposed to exist" || true; }
check_files_eq() { cmp "$1" "$2" || die "$1 and $2 did not match"; }
check_keys_eq() { check_files_eq "${SRC}/keys/${1}" "${ME}/keys/${1}"; }

DATA_DIR=`mktemp -d -t tor_keygen_tests.XXXXXX`
if [ -z "$DATA_DIR" ]; then
  echo "Failure: mktemp invocation returned empty string" >&2
  exit 3
fi
if [ ! -d "$DATA_DIR" ]; then
  echo "Failure: mktemp invocation result doesn't point to directory" >&2
  exit 3
fi
trap "rm -rf '$DATA_DIR'" 0

touch "${DATA_DIR}/empty_torrc"

QUIETLY="--hush"
TOR="${TOR_BINARY} ${QUIETLY} --DisableNetwork 1 --ShutdownWaitLength 0 --ORPort 12345 --ExitRelay 0 -f ${DATA_DIR}/empty_torrc"

# Step 1: Start Tor with --list-fingerprint.  Make sure everything is there.
mkdir "${DATA_DIR}/orig"
${TOR} --DataDirectory "${DATA_DIR}/orig" --list-fingerprint > /dev/null

check_dir "${DATA_DIR}/orig/keys"
check_file "${DATA_DIR}/orig/keys/ed25519_master_id_public_key"
check_file "${DATA_DIR}/orig/keys/ed25519_master_id_secret_key"
check_file "${DATA_DIR}/orig/keys/ed25519_signing_cert"
check_file "${DATA_DIR}/orig/keys/ed25519_signing_secret_key"

# Step 2: Start Tor with --keygen.  Make sure everything is there.
mkdir "${DATA_DIR}/keygen"
${TOR} --DataDirectory "${DATA_DIR}/keygen" --keygen --no-passphrase 2>"${DATA_DIR}/keygen/stderr"
grep "Not encrypting the secret key" "${DATA_DIR}/keygen/stderr" >/dev/null || die "Tor didn't declare that there would be no encryption"

check_dir "${DATA_DIR}/keygen/keys"
check_file "${DATA_DIR}/keygen/keys/ed25519_master_id_public_key"
check_file "${DATA_DIR}/keygen/keys/ed25519_master_id_secret_key"
check_file "${DATA_DIR}/keygen/keys/ed25519_signing_cert"
check_file "${DATA_DIR}/keygen/keys/ed25519_signing_secret_key"

# Step 3: Start Tor with --keygen and a passphrase.
#         Make sure everything is there.
mkdir "${DATA_DIR}/encrypted"
echo "passphrase" | ${TOR} --DataDirectory "${DATA_DIR}/encrypted" --keygen --passphrase-fd 0

check_dir "${DATA_DIR}/encrypted/keys"
check_file "${DATA_DIR}/encrypted/keys/ed25519_master_id_public_key"
check_file "${DATA_DIR}/encrypted/keys/ed25519_master_id_secret_key_encrypted"
check_file "${DATA_DIR}/encrypted/keys/ed25519_signing_cert"
check_file "${DATA_DIR}/encrypted/keys/ed25519_signing_secret_key"


echo "=== Starting tests."

#
# The "case X" numbers below come from s7r's email on
#   https://lists.torproject.org/pipermail/tor-dev/2015-August/009204.html


# Case 2a: Missing secret key, public key exists, start tor.

if [ "$CASE2A" = 1 ]; then

ME="${DATA_DIR}/case2a"
SRC="${DATA_DIR}/orig"
mkdir -p "${ME}/keys"
cp "${SRC}/keys/ed25519_master_id_public_key" "${ME}/keys/"
${TOR} --DataDirectory "${ME}" --list-fingerprint && die "Somehow succeeded when missing secret key, certs" || true
check_files_eq "${SRC}/keys/ed25519_master_id_public_key" "${ME}/keys/ed25519_master_id_public_key"

echo "==== Case 2A ok"
fi

# Case 2b: Encrypted secret key, public key exists, start tor.

if [ "$CASE2B" = 1 ]; then

ME="${DATA_DIR}/case2b"
SRC="${DATA_DIR}/encrypted"

mkdir -p "${ME}/keys"
cp "${SRC}/keys/ed25519_master_id_public_key" "${ME}/keys/"
cp "${SRC}/keys/ed25519_master_id_secret_key_encrypted" "${ME}/keys/"
${TOR} --DataDirectory "${ME}" --list-fingerprint && dir "Somehow succeeded with encrypted secret key, missing certs"

check_files_eq "${SRC}/keys/ed25519_master_id_public_key" "${ME}/keys/ed25519_master_id_public_key"
check_files_eq "${SRC}/keys/ed25519_master_id_secret_key_encrypted" "${ME}/keys/ed25519_master_id_secret_key_encrypted"

echo "==== Case 2B ok"

fi

# Case 3a: Start Tor with only master key.

if [ "$CASE3A" = 1 ]; then

ME="${DATA_DIR}/case3a"
SRC="${DATA_DIR}/orig"

mkdir -p "${ME}/keys"
cp "${SRC}/keys/ed25519_master_id_"* "${ME}/keys/"
${TOR} --DataDirectory "${ME}" --list-fingerprint || die "Tor failed when starting with only master key"
check_files_eq "${SRC}/keys/ed25519_master_id_public_key" "${ME}/keys/ed25519_master_id_public_key"
check_files_eq "${SRC}/keys/ed25519_master_id_secret_key" "${ME}/keys/ed25519_master_id_secret_key"
check_file "${ME}/keys/ed25519_signing_cert"
check_file "${ME}/keys/ed25519_signing_secret_key"

echo "==== Case 3A ok"

fi

# Case 3b: Call keygen with only unencrypted master key.

if [ "$CASE3B" = 1 ]; then

ME="${DATA_DIR}/case3b"
SRC="${DATA_DIR}/orig"

mkdir -p "${ME}/keys"
cp "${SRC}/keys/ed25519_master_id_"* "${ME}/keys/"
${TOR} --DataDirectory "${ME}" --keygen || die "Keygen failed with only master key"
check_files_eq "${SRC}/keys/ed25519_master_id_public_key" "${ME}/keys/ed25519_master_id_public_key"
check_files_eq "${SRC}/keys/ed25519_master_id_secret_key" "${ME}/keys/ed25519_master_id_secret_key"
check_file "${ME}/keys/ed25519_signing_cert"
check_file "${ME}/keys/ed25519_signing_secret_key"

echo "==== Case 3B ok"

fi

# Case 3c: Call keygen with only encrypted master key.

if [ "$CASE3C" = 1 ]; then

ME="${DATA_DIR}/case3c"
SRC="${DATA_DIR}/encrypted"

mkdir -p "${ME}/keys"
cp "${SRC}/keys/ed25519_master_id_"* "${ME}/keys/"
echo "passphrase" | ${TOR} --DataDirectory "${ME}" --keygen --passphrase-fd 0 || die "Keygen failed with only encrypted master key"
check_files_eq "${SRC}/keys/ed25519_master_id_public_key" "${ME}/keys/ed25519_master_id_public_key"
check_files_eq "${SRC}/keys/ed25519_master_id_secret_key_encrypted" "${ME}/keys/ed25519_master_id_secret_key_encrypted"
check_file "${ME}/keys/ed25519_signing_cert"
check_file "${ME}/keys/ed25519_signing_secret_key"

echo "==== Case 3C ok"

fi

# Case 4: Make a new data directory with only an unencrypted secret key.
#         Then start tor.  The rest should become correct.

if [ "$CASE4" = 1 ]; then

ME="${DATA_DIR}/case4"
SRC="${DATA_DIR}/orig"

mkdir -p "${ME}/keys"
cp "${SRC}/keys/ed25519_master_id_secret_key" "${ME}/keys/"
${TOR} --DataDirectory "${ME}" --list-fingerprint || die "Tor wouldn't start with only unencrypted secret key"
check_file "${ME}/keys/ed25519_master_id_public_key"
check_file "${ME}/keys/ed25519_signing_cert"
check_file "${ME}/keys/ed25519_signing_secret_key"
${TOR} --DataDirectory "${ME}" --list-fingerprint || die "Tor wouldn't start again after starting once with only unencrypted secret key."

echo "==== Case 4 ok"

fi

# Case 5: Make a new data directory with only an encrypted secret key.

if [ "$CASE5" = 1 ]; then

ME="${DATA_DIR}/case5"
SRC="${DATA_DIR}/encrypted"

mkdir -p "${ME}/keys"
cp "${SRC}/keys/ed25519_master_id_secret_key_encrypted" "${ME}/keys/"
${TOR} --DataDirectory "${ME}" --list-fingerprint && die "Tor started with only encrypted secret key!"
check_no_file "${ME}/keys/ed25519_master_id_public_key"
check_no_file "${ME}/keys/ed25519_master_id_public_key"

echo "==== Case 5 ok"

fi

# Case 6: Make a new data directory with encrypted secret key and public key

if [ "$CASE6" = 1 ]; then

ME="${DATA_DIR}/case6"
SRC="${DATA_DIR}/encrypted"

mkdir -p "${ME}/keys"
cp "${SRC}/keys/ed25519_master_id_secret_key_encrypted" "${ME}/keys/"
cp "${SRC}/keys/ed25519_master_id_public_key" "${ME}/keys/"
${TOR} --DataDirectory "${ME}" --list-fingerprint && die "Tor started with encrypted secret key and no certs" || true
check_no_file "${ME}/keys/ed25519_signing_cert"
check_no_file "${ME}/keys/ed25519_signing_secret_key"

echo "==== Case 6 ok"

fi

# Case 7: Make a new data directory with unencrypted secret key and
# certificates; missing master public.

if [ "$CASE7" = 1 ]; then

ME="${DATA_DIR}/case7"
SRC="${DATA_DIR}/keygen"

mkdir -p "${ME}/keys"
cp "${SRC}/keys/ed25519_master_id_secret_key" "${ME}/keys/"
cp "${SRC}/keys/ed25519_signing_cert" "${ME}/keys/"
cp "${SRC}/keys/ed25519_signing_secret_key" "${ME}/keys/"

${TOR} --DataDirectory "${ME}" --list-fingerprint || die "Failed when starting with missing public key"
check_keys_eq ed25519_master_id_secret_key
check_keys_eq ed25519_master_id_public_key
check_keys_eq ed25519_signing_secret_key
check_keys_eq ed25519_signing_cert

echo "==== Case 7 ok"

fi

# Case 8: offline master secret key.

if [ "$CASE8" = 1 ]; then

ME="${DATA_DIR}/case8"
SRC="${DATA_DIR}/keygen"

mkdir -p "${ME}/keys"
cp "${SRC}/keys/ed25519_master_id_public_key" "${ME}/keys/"
cp "${SRC}/keys/ed25519_signing_cert" "${ME}/keys/"
cp "${SRC}/keys/ed25519_signing_secret_key" "${ME}/keys/"

${TOR} --DataDirectory "${ME}" --list-fingerprint || die "Failed when starting with offline secret key"
check_no_file "${ME}/keys/ed25519_master_id_secret_key"
check_keys_eq ed25519_master_id_public_key
check_keys_eq ed25519_signing_secret_key
check_keys_eq ed25519_signing_cert

echo "==== Case 8 ok"

fi

# Case 9: signing cert and secret key provided; could infer master key.

if [ "$CASE9" = 1 ]; then

ME="${DATA_DIR}/case9"
SRC="${DATA_DIR}/keygen"

mkdir -p "${ME}/keys"
cp "${SRC}/keys/ed25519_signing_cert" "${ME}/keys/"
cp "${SRC}/keys/ed25519_signing_secret_key" "${ME}/keys/"

${TOR} --DataDirectory "${ME}" --list-fingerprint || die "Failed when starting with only signing material"
check_no_file "${ME}/keys/ed25519_master_id_secret_key"
check_no_file "${ME}/keys/ed25519_master_id_public_key"
check_keys_eq ed25519_signing_secret_key
check_keys_eq ed25519_signing_cert

echo "==== Case 9 ok"

fi


# Case 10: master key mismatch.

if [ "$CASE10" = 1 ]; then

ME="${DATA_DIR}/case10"
SRC="${DATA_DIR}/keygen"
OTHER="${DATA_DIR}/orig"

mkdir -p "${ME}/keys"
cp "${SRC}/keys/ed25519_master_id_public_key" "${ME}/keys/"
cp "${OTHER}/keys/ed25519_master_id_secret_key" "${ME}/keys/"

${TOR} --DataDirectory "${ME}" --list-fingerprint && die "Successfully started with mismatched keys!?" || true

echo "==== Case 10 ok"

fi


# Check cert-only.

