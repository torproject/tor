/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_common.c
 * \brief Contains code shared between different HS protocol version as well
 *        as useful data structures and accessors used by other subsystems.
 *        The rendcommon.c should only contains code relating to the v2
 *        protocol.
 **/

#define HS_COMMON_PRIVATE

#include "or.h"

#include "config.h"
#include "networkstatus.h"
#include "hs_cache.h"
#include "hs_common.h"
#include "hs_service.h"
#include "rendcommon.h"
#include "rendservice.h"
#include "shared_random.h"

/* Ed25519 Basepoint value. Taken from section 5 of
 * https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-03 */
static const char *str_ed25519_basepoint =
  "(15112221349535400772501151409588531511"
  "454012693041857206046113283949847762202, "
  "463168356949264781694283940034751631413"
  "07993866256225615783033603165251855960)";

/* Allocate and return a string containing the path to filename in directory.
 * This function will never return NULL. The caller must free this path. */
char *
hs_path_from_filename(const char *directory, const char *filename)
{
  char *file_path = NULL;

  tor_assert(directory);
  tor_assert(filename);

  tor_asprintf(&file_path, "%s%s%s", directory, PATH_SEPARATOR, filename);
  return file_path;
}

/* Make sure that the directory for <b>service</b> is private, using the config
 * <b>username</b>.
 * If <b>create</b> is true:
 *  - if the directory exists, change permissions if needed,
 *  - if the directory does not exist, create it with the correct permissions.
 * If <b>create</b> is false:
 *  - if the directory exists, check permissions,
 *  - if the directory does not exist, check if we think we can create it.
 * Return 0 on success, -1 on failure. */
int
hs_check_service_private_dir(const char *username, const char *path,
                             unsigned int dir_group_readable,
                             unsigned int create)
{
  cpd_check_t check_opts = CPD_NONE;

  tor_assert(path);

  if (create) {
    check_opts |= CPD_CREATE;
  } else {
    check_opts |= CPD_CHECK_MODE_ONLY;
    check_opts |= CPD_CHECK;
  }
  if (dir_group_readable) {
    check_opts |= CPD_GROUP_READ;
  }
  /* Check/create directory */
  if (check_private_dir(path, check_opts, username) < 0) {
    return -1;
  }
  return 0;
}

/** Get the default HS time period length in minutes from the consensus. */
STATIC uint64_t
get_time_period_length(void)
{
  int32_t time_period_length = networkstatus_get_param(NULL, "hsdir-interval",
                                             HS_TIME_PERIOD_LENGTH_DEFAULT,
                                             HS_TIME_PERIOD_LENGTH_MIN,
                                             HS_TIME_PERIOD_LENGTH_MAX);
  /* Make sure it's a positive value. */
  tor_assert(time_period_length >= 0);
  /* uint64_t will always be able to contain a int32_t */
  return (uint64_t) time_period_length;
}

/** Get the HS time period number at time <b>now</b> */
uint64_t
hs_get_time_period_num(time_t now)
{
  uint64_t time_period_num;
  uint64_t time_period_length = get_time_period_length();
  uint64_t minutes_since_epoch = now / 60;

  /* Now subtract half a day to fit the prop224 time period schedule (see
   * section [TIME-PERIODS]). */
  tor_assert(minutes_since_epoch > HS_TIME_PERIOD_ROTATION_OFFSET);
  minutes_since_epoch -= HS_TIME_PERIOD_ROTATION_OFFSET;

  /* Calculate the time period */
  time_period_num = minutes_since_epoch / time_period_length;
  return time_period_num;
}

/** Get the number of the _upcoming_ HS time period, given that the current
 *  time is <b>now</b>. */
uint64_t
hs_get_next_time_period_num(time_t now)
{
  return hs_get_time_period_num(now) + 1;
}

/* Create a new rend_data_t for a specific given <b>version</b>.
 * Return a pointer to the newly allocated data structure. */
static rend_data_t *
rend_data_alloc(uint32_t version)
{
  rend_data_t *rend_data = NULL;

  switch (version) {
  case HS_VERSION_TWO:
  {
    rend_data_v2_t *v2 = tor_malloc_zero(sizeof(*v2));
    v2->base_.version = HS_VERSION_TWO;
    v2->base_.hsdirs_fp = smartlist_new();
    rend_data = &v2->base_;
    break;
  }
  default:
    tor_assert(0);
    break;
  }

  return rend_data;
}

/** Free all storage associated with <b>data</b> */
void
rend_data_free(rend_data_t *data)
{
  if (!data) {
    return;
  }
  /* By using our allocation function, this should always be set. */
  tor_assert(data->hsdirs_fp);
  /* Cleanup the HSDir identity digest. */
  SMARTLIST_FOREACH(data->hsdirs_fp, char *, d, tor_free(d));
  smartlist_free(data->hsdirs_fp);
  /* Depending on the version, cleanup. */
  switch (data->version) {
  case HS_VERSION_TWO:
  {
    rend_data_v2_t *v2_data = TO_REND_DATA_V2(data);
    tor_free(v2_data);
    break;
  }
  default:
    tor_assert(0);
  }
}

/* Allocate and return a deep copy of <b>data</b>. */
rend_data_t *
rend_data_dup(const rend_data_t *data)
{
  rend_data_t *data_dup = NULL;
  smartlist_t *hsdirs_fp = smartlist_new();

  tor_assert(data);
  tor_assert(data->hsdirs_fp);

  SMARTLIST_FOREACH(data->hsdirs_fp, char *, fp,
                    smartlist_add(hsdirs_fp, tor_memdup(fp, DIGEST_LEN)));

  switch (data->version) {
  case HS_VERSION_TWO:
  {
    rend_data_v2_t *v2_data = tor_memdup(TO_REND_DATA_V2(data),
                                         sizeof(*v2_data));
    data_dup = &v2_data->base_;
    data_dup->hsdirs_fp = hsdirs_fp;
    break;
  }
  default:
    tor_assert(0);
    break;
  }

  return data_dup;
}

/* Compute the descriptor ID for each HS descriptor replica and save them. A
 * valid onion address must be present in the <b>rend_data</b>.
 *
 * Return 0 on success else -1. */
static int
compute_desc_id(rend_data_t *rend_data)
{
  int ret = 0;
  unsigned replica;
  time_t now = time(NULL);

  tor_assert(rend_data);

  switch (rend_data->version) {
  case HS_VERSION_TWO:
  {
    rend_data_v2_t *v2_data = TO_REND_DATA_V2(rend_data);
    /* Compute descriptor ID for each replicas. */
    for (replica = 0; replica < ARRAY_LENGTH(v2_data->descriptor_id);
         replica++) {
      ret = rend_compute_v2_desc_id(v2_data->descriptor_id[replica],
                                    v2_data->onion_address,
                                    v2_data->descriptor_cookie,
                                    now, replica);
      if (ret < 0) {
        goto end;
      }
    }
    break;
  }
  default:
    tor_assert(0);
  }

 end:
  return ret;
}

/* Allocate and initialize a rend_data_t object for a service using the
 * provided arguments. All arguments are optional (can be NULL), except from
 * <b>onion_address</b> which MUST be set. The <b>pk_digest</b> is the hash of
 * the service private key. The <b>cookie</b> is the rendezvous cookie and
 * <b>auth_type</b> is which authentiation this service is configured with.
 *
 * Return a valid rend_data_t pointer. This only returns a version 2 object of
 * rend_data_t. */
rend_data_t *
rend_data_service_create(const char *onion_address, const char *pk_digest,
                         const uint8_t *cookie, rend_auth_type_t auth_type)
{
  /* Create a rend_data_t object for version 2. */
  rend_data_t *rend_data = rend_data_alloc(HS_VERSION_TWO);
  rend_data_v2_t *v2= TO_REND_DATA_V2(rend_data);

  /* We need at least one else the call is wrong. */
  tor_assert(onion_address != NULL);

  if (pk_digest) {
    memcpy(v2->rend_pk_digest, pk_digest, sizeof(v2->rend_pk_digest));
  }
  if (cookie) {
    memcpy(rend_data->rend_cookie, cookie, sizeof(rend_data->rend_cookie));
  }

  strlcpy(v2->onion_address, onion_address, sizeof(v2->onion_address));
  v2->auth_type = auth_type;

  return rend_data;
}

/* Allocate and initialize a rend_data_t object for a client request using the
 * given arguments. Either an onion address or a descriptor ID is needed. Both
 * can be given but in this case only the onion address will be used to make
 * the descriptor fetch. The <b>cookie</b> is the rendezvous cookie and
 * <b>auth_type</b> is which authentiation the service is configured with.
 *
 * Return a valid rend_data_t pointer or NULL on error meaning the
 * descriptor IDs couldn't be computed from the given data. */
rend_data_t *
rend_data_client_create(const char *onion_address, const char *desc_id,
                        const char *cookie, rend_auth_type_t auth_type)
{
  /* Create a rend_data_t object for version 2. */
  rend_data_t *rend_data = rend_data_alloc(HS_VERSION_TWO);
  rend_data_v2_t *v2= TO_REND_DATA_V2(rend_data);

  /* We need at least one else the call is wrong. */
  tor_assert(onion_address != NULL || desc_id != NULL);

  if (cookie) {
    memcpy(v2->descriptor_cookie, cookie, sizeof(v2->descriptor_cookie));
  }
  if (desc_id) {
    memcpy(v2->desc_id_fetch, desc_id, sizeof(v2->desc_id_fetch));
  }
  if (onion_address) {
    strlcpy(v2->onion_address, onion_address, sizeof(v2->onion_address));
    if (compute_desc_id(rend_data) < 0) {
      goto error;
    }
  }

  v2->auth_type = auth_type;

  return rend_data;

 error:
  rend_data_free(rend_data);
  return NULL;
}

/* Return the onion address from the rend data. Depending on the version,
 * the size of the address can vary but it's always NUL terminated. */
const char *
rend_data_get_address(const rend_data_t *rend_data)
{
  tor_assert(rend_data);

  switch (rend_data->version) {
  case HS_VERSION_TWO:
    return TO_REND_DATA_V2(rend_data)->onion_address;
  default:
    /* We should always have a supported version. */
    tor_assert(0);
  }
}

/* Return the descriptor ID for a specific replica number from the rend
 * data. The returned data is a binary digest and depending on the version its
 * size can vary. The size of the descriptor ID is put in <b>len_out</b> if
 * non NULL. */
const char *
rend_data_get_desc_id(const rend_data_t *rend_data, uint8_t replica,
                      size_t *len_out)
{
  tor_assert(rend_data);

  switch (rend_data->version) {
  case HS_VERSION_TWO:
    tor_assert(replica < REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS);
    if (len_out) {
      *len_out = DIGEST_LEN;
    }
    return TO_REND_DATA_V2(rend_data)->descriptor_id[replica];
  default:
    /* We should always have a supported version. */
    tor_assert(0);
  }
}

/* Return the public key digest using the given <b>rend_data</b>. The size of
 * the digest is put in <b>len_out</b> (if set) which can differ depending on
 * the version. */
const uint8_t *
rend_data_get_pk_digest(const rend_data_t *rend_data, size_t *len_out)
{
  tor_assert(rend_data);

  switch (rend_data->version) {
  case HS_VERSION_TWO:
  {
    const rend_data_v2_t *v2_data = TO_REND_DATA_V2(rend_data);
    if (len_out) {
      *len_out = sizeof(v2_data->rend_pk_digest);
    }
    return (const uint8_t *) v2_data->rend_pk_digest;
  }
  default:
    /* We should always have a supported version. */
    tor_assert(0);
  }
}

/* Using the given time period number, compute the disaster shared random
 * value and put it in srv_out. It MUST be at least DIGEST256_LEN bytes. */
static void
get_disaster_srv(uint64_t time_period_num, uint8_t *srv_out)
{
  crypto_digest_t *digest;

  tor_assert(srv_out);

  digest = crypto_digest256_new(DIGEST_SHA3_256);
  /* Setup payload: H("shared-random-disaster" | INT_8(period_num)) */
  crypto_digest_add_bytes(digest, HS_SRV_DISASTER_PREFIX,
                          HS_SRV_DISASTER_PREFIX_LEN);
  crypto_digest_add_bytes(digest, (const char *) &time_period_num,
                          sizeof(time_period_num));
  crypto_digest_get_digest(digest, (char *) srv_out, DIGEST256_LEN);
  crypto_digest_free(digest);
}

/* When creating a blinded key, we need a parameter which construction is as
 * follow: H(pubkey | [secret] | ed25519-basepoint | nonce).
 *
 * The nonce has a pre-defined format which uses the time period number
 * period_num and the start of the period in second start_time_period.
 *
 * The secret of size secret_len is optional meaning that it can be NULL and
 * thus will be ignored for the param construction.
 *
 * The result is put in param_out. */
static void
build_blinded_key_param(const ed25519_public_key_t *pubkey,
                        const uint8_t *secret, size_t secret_len,
                        uint64_t period_num, uint64_t start_time_period,
                        uint8_t *param_out)
{
  size_t offset = 0;
  uint8_t nonce[HS_KEYBLIND_NONCE_LEN];
  crypto_digest_t *digest;

  tor_assert(pubkey);
  tor_assert(param_out);

  /* Create the nonce N. The construction is as follow:
   *    N = "key-blind" || INT_8(period_num) || INT_8(start_period_sec) */
  memcpy(nonce, HS_KEYBLIND_NONCE_PREFIX, HS_KEYBLIND_NONCE_PREFIX_LEN);
  offset += HS_KEYBLIND_NONCE_PREFIX_LEN;
  set_uint64(nonce + offset, period_num);
  offset += sizeof(uint64_t);
  set_uint64(nonce + offset, start_time_period);
  offset += sizeof(uint64_t);
  tor_assert(offset == HS_KEYBLIND_NONCE_LEN);

  /* Generate the parameter h and the construction is as follow:
   *    h = H(pubkey | [secret] | ed25519-basepoint | nonce) */
  digest = crypto_digest256_new(DIGEST_SHA3_256);
  crypto_digest_add_bytes(digest, (char *) pubkey, ED25519_PUBKEY_LEN);
  /* Optional secret. */
  if (secret) {
    crypto_digest_add_bytes(digest, (char *) secret, secret_len);
  }
  crypto_digest_add_bytes(digest, str_ed25519_basepoint,
                          strlen(str_ed25519_basepoint));
  crypto_digest_add_bytes(digest, (char *) nonce, sizeof(nonce));

  /* Extract digest and put it in the param. */
  crypto_digest_get_digest(digest, (char *) param_out, DIGEST256_LEN);
  crypto_digest_free(digest);
}

/* Using an ed25519 public key and version to build the checksum of an
 * address. Put in checksum_out. Format is:
 *    SHA3-256(".onion checksum" || PUBKEY || VERSION)
 *
 * checksum_out must be large enough to receive 32 bytes (DIGEST256_LEN). */
static void
build_hs_checksum(const ed25519_public_key_t *key, uint8_t version,
                  uint8_t *checksum_out)
{
  size_t offset = 0;
  char data[HS_SERVICE_ADDR_CHECKSUM_INPUT_LEN];

  /* Build checksum data. */
  memcpy(data, HS_SERVICE_ADDR_CHECKSUM_PREFIX,
         HS_SERVICE_ADDR_CHECKSUM_PREFIX_LEN);
  offset += HS_SERVICE_ADDR_CHECKSUM_PREFIX_LEN;
  memcpy(data + offset, key->pubkey, ED25519_PUBKEY_LEN);
  offset += ED25519_PUBKEY_LEN;
  set_uint8(data + offset, version);
  offset += sizeof(version);
  tor_assert(offset == HS_SERVICE_ADDR_CHECKSUM_INPUT_LEN);

  /* Hash the data payload to create the checksum. */
  crypto_digest256((char *) checksum_out, data, sizeof(data),
                   DIGEST_SHA3_256);
}

/* Using an ed25519 public key, checksum and version to build the binary
 * representation of a service address. Put in addr_out. Format is:
 *    addr_out = PUBKEY || CHECKSUM || VERSION
 *
 * addr_out must be large enough to receive HS_SERVICE_ADDR_LEN bytes. */
static void
build_hs_address(const ed25519_public_key_t *key, const uint8_t *checksum,
                 uint8_t version, char *addr_out)
{
  size_t offset = 0;

  tor_assert(key);
  tor_assert(checksum);

  memcpy(addr_out, key->pubkey, ED25519_PUBKEY_LEN);
  offset += ED25519_PUBKEY_LEN;
  memcpy(addr_out + offset, checksum, HS_SERVICE_ADDR_CHECKSUM_LEN_USED);
  offset += HS_SERVICE_ADDR_CHECKSUM_LEN_USED;
  set_uint8(addr_out + offset, version);
  offset += sizeof(uint8_t);
  tor_assert(offset == HS_SERVICE_ADDR_LEN);
}

/* Helper for hs_parse_address(): Using a binary representation of a service
 * address, parse its content into the key_out, checksum_out and version_out.
 * Any out variable can be NULL in case the caller would want only one field.
 * checksum_out MUST at least be 2 bytes long. address must be at least
 * HS_SERVICE_ADDR_LEN bytes but doesn't need to be NUL terminated. */
static void
hs_parse_address_impl(const char *address, ed25519_public_key_t *key_out,
                      uint8_t *checksum_out, uint8_t *version_out)
{
  size_t offset = 0;

  tor_assert(address);

  if (key_out) {
    /* First is the key. */
    memcpy(key_out->pubkey, address, ED25519_PUBKEY_LEN);
  }
  offset += ED25519_PUBKEY_LEN;
  if (checksum_out) {
    /* Followed by a 2 bytes checksum. */
    memcpy(checksum_out, address + offset, HS_SERVICE_ADDR_CHECKSUM_LEN_USED);
  }
  offset += HS_SERVICE_ADDR_CHECKSUM_LEN_USED;
  if (version_out) {
    /* Finally, version value is 1 byte. */
    *version_out = get_uint8(address + offset);
  }
  offset += sizeof(uint8_t);
  /* Extra safety. */
  tor_assert(offset == HS_SERVICE_ADDR_LEN);
}

/* Using the given identity public key and a blinded public key, compute the
 * subcredential and put it in subcred_out. This can't fail. */
void
hs_get_subcredential(const ed25519_public_key_t *identity_pk,
                     const ed25519_public_key_t *blinded_pk,
                     uint8_t *subcred_out)
{
  uint8_t credential[DIGEST256_LEN];
  crypto_digest_t *digest;

  tor_assert(identity_pk);
  tor_assert(blinded_pk);
  tor_assert(subcred_out);

  /* First, build the credential. Construction is as follow:
   *  credential = H("credential" | public-identity-key) */
  digest = crypto_digest256_new(DIGEST_SHA3_256);
  crypto_digest_add_bytes(digest, HS_CREDENTIAL_PREFIX,
                          HS_CREDENTIAL_PREFIX_LEN);
  crypto_digest_add_bytes(digest, (const char *) identity_pk->pubkey,
                          ED25519_PUBKEY_LEN);
  crypto_digest_get_digest(digest, (char *) credential, DIGEST256_LEN);
  crypto_digest_free(digest);

  /* Now, compute the subcredential. Construction is as follow:
   *  subcredential = H("subcredential" | credential | blinded-public-key). */
  digest = crypto_digest256_new(DIGEST_SHA3_256);
  crypto_digest_add_bytes(digest, HS_SUBCREDENTIAL_PREFIX,
                          HS_SUBCREDENTIAL_PREFIX_LEN);
  crypto_digest_add_bytes(digest, (const char *) credential,
                          sizeof(credential));
  crypto_digest_add_bytes(digest, (const char *) blinded_pk->pubkey,
                          ED25519_PUBKEY_LEN);
  crypto_digest_get_digest(digest, (char *) subcred_out, DIGEST256_LEN);
  crypto_digest_free(digest);
}

/* Using a base32 representation of a service address, parse its content into
 * the key_out, checksum_out and version_out. Any out variable can be NULL in
 * case the caller would want only one field. checksum_out MUST at least be 2
 * bytes long.
 *
 * Return 0 if parsing went well; return -1 in case of error. */
int
hs_parse_address(const char *address, ed25519_public_key_t *key_out,
                 uint8_t *checksum_out, uint8_t *version_out)
{
  char decoded[HS_SERVICE_ADDR_LEN];

  tor_assert(address);

  /* Obvious length check. */
  if (strlen(address) != HS_SERVICE_ADDR_LEN_BASE32) {
    log_warn(LD_REND, "Service address %s has an invalid length. "
                      "Expected %lu but got %lu.",
             escaped_safe_str(address),
             (unsigned long) HS_SERVICE_ADDR_LEN_BASE32,
             (unsigned long) strlen(address));
    goto invalid;
  }

  /* Decode address so we can extract needed fields. */
  if (base32_decode(decoded, sizeof(decoded), address, strlen(address)) < 0) {
    log_warn(LD_REND, "Service address %s can't be decoded.",
             escaped_safe_str(address));
    goto invalid;
  }

  /* Parse the decoded address into the fields we need. */
  hs_parse_address_impl(decoded, key_out, checksum_out, version_out);

  return 0;
 invalid:
  return -1;
}

/* Validate a given onion address. The length, the base32 decoding and
 * checksum are validated. Return 1 if valid else 0. */
int
hs_address_is_valid(const char *address)
{
  uint8_t version;
  uint8_t checksum[HS_SERVICE_ADDR_CHECKSUM_LEN_USED];
  uint8_t target_checksum[DIGEST256_LEN];
  ed25519_public_key_t key;

  /* Parse the decoded address into the fields we need. */
  if (hs_parse_address(address, &key, checksum, &version) < 0) {
    goto invalid;
  }

  /* Get the checksum it's suppose to be and compare it with what we have
   * encoded in the address. */
  build_hs_checksum(&key, version, target_checksum);
  if (tor_memcmp(checksum, target_checksum, sizeof(checksum))) {
    log_warn(LD_REND, "Service address %s invalid checksum.",
             escaped_safe_str(address));
    goto invalid;
  }

  /* Valid address. */
  return 1;
 invalid:
  return 0;
}

/* Build a service address using an ed25519 public key and a given version.
 * The returned address is base32 encoded and put in addr_out. The caller MUST
 * make sure the addr_out is at least HS_SERVICE_ADDR_LEN_BASE32 + 1 long.
 *
 * Format is as follow:
 *     base32(PUBKEY || CHECKSUM || VERSION)
 *     CHECKSUM = H(".onion checksum" || PUBKEY || VERSION)
 * */
void
hs_build_address(const ed25519_public_key_t *key, uint8_t version,
                 char *addr_out)
{
  uint8_t checksum[DIGEST256_LEN];
  char address[HS_SERVICE_ADDR_LEN];

  tor_assert(key);
  tor_assert(addr_out);

  /* Get the checksum of the address. */
  build_hs_checksum(key, version, checksum);
  /* Get the binary address representation. */
  build_hs_address(key, checksum, version, address);

  /* Encode the address. addr_out will be NUL terminated after this. */
  base32_encode(addr_out, HS_SERVICE_ADDR_LEN_BASE32 + 1, address,
                sizeof(address));
  /* Validate what we just built. */
  tor_assert(hs_address_is_valid(addr_out));
}

/* Return a newly allocated copy of lspec. */
link_specifier_t *
hs_link_specifier_dup(const link_specifier_t *lspec)
{
  link_specifier_t *dup = link_specifier_new();
  memcpy(dup, lspec, sizeof(*dup));
  /* The unrecognized field is a dynamic array so make sure to copy its
   * content and not the pointer. */
  link_specifier_setlen_un_unrecognized(
                        dup, link_specifier_getlen_un_unrecognized(lspec));
  if (link_specifier_getlen_un_unrecognized(dup)) {
    memcpy(link_specifier_getarray_un_unrecognized(dup),
           link_specifier_getconstarray_un_unrecognized(lspec),
           link_specifier_getlen_un_unrecognized(dup));
  }
  return dup;
}

/* From a given ed25519 public key pk and an optional secret, compute a
 * blinded public key and put it in blinded_pk_out. This is only useful to
 * the client side because the client only has access to the identity public
 * key of the service. */
void
hs_build_blinded_pubkey(const ed25519_public_key_t *pk,
                        const uint8_t *secret, size_t secret_len,
                        uint64_t time_period_num,
                        ed25519_public_key_t *blinded_pk_out)
{
  /* Our blinding key API requires a 32 bytes parameter. */
  uint8_t param[DIGEST256_LEN];

  tor_assert(pk);
  tor_assert(blinded_pk_out);
  tor_assert(!tor_mem_is_zero((char *) pk, ED25519_PUBKEY_LEN));

  build_blinded_key_param(pk, secret, secret_len,
                          time_period_num, get_time_period_length(), param);
  ed25519_public_blind(blinded_pk_out, pk, param);
}

/* From a given ed25519 keypair kp and an optional secret, compute a blinded
 * keypair for the current time period and put it in blinded_kp_out. This is
 * only useful by the service side because the client doesn't have access to
 * the identity secret key. */
void
hs_build_blinded_keypair(const ed25519_keypair_t *kp,
                         const uint8_t *secret, size_t secret_len,
                         uint64_t time_period_num,
                         ed25519_keypair_t *blinded_kp_out)
{
  /* Our blinding key API requires a 32 bytes parameter. */
  uint8_t param[DIGEST256_LEN];

  tor_assert(kp);
  tor_assert(blinded_kp_out);
  /* Extra safety. A zeroed key is bad. */
  tor_assert(!tor_mem_is_zero((char *) &kp->pubkey, ED25519_PUBKEY_LEN));
  tor_assert(!tor_mem_is_zero((char *) &kp->seckey, ED25519_SECKEY_LEN));

  build_blinded_key_param(&kp->pubkey, secret, secret_len,
                          time_period_num, get_time_period_length(), param);
  ed25519_keypair_blind(blinded_kp_out, kp, param);
}

/* Return true if overlap mode is active given the date in consensus. If
 * consensus is NULL, then we use the latest live consensus we can find. */
int
hs_overlap_mode_is_active(const networkstatus_t *consensus, time_t now)
{
  struct tm valid_after_tm;

  if (!consensus) {
    consensus = networkstatus_get_live_consensus(now);
    if (!consensus) {
      return 0;
    }
  }

  /* XXX: Futur commits will change this to a slot system so it can be
   * fine tuned better for testing networks in terms of timings. */

  /* From the spec: "Specifically, when a hidden service fetches a consensus
   * with "valid-after" between 00:00UTC and 12:00UTC, it goes into
   * "descriptor overlap" mode." */
  tor_gmtime_r(&consensus->valid_after, &valid_after_tm);
  if (valid_after_tm.tm_hour > 0 && valid_after_tm.tm_hour < 12) {
    return 1;
  }
  return 0;
}

/* Return 1 if any virtual port in ports needs a circuit with good uptime.
 * Else return 0. */
int
hs_service_requires_uptime_circ(const smartlist_t *ports)
{
  tor_assert(ports);

  SMARTLIST_FOREACH_BEGIN(ports, rend_service_port_config_t *, p) {
    if (smartlist_contains_int_as_string(get_options()->LongLivedPorts,
                                         p->virtual_port)) {
      return 1;
    }
  } SMARTLIST_FOREACH_END(p);
  return 0;
}

/* Build hs_index which is used to find the responsible hsdirs. This index
 * value is used to select the responsible HSDir where their hsdir_index is
 * closest to this value.
 *    SHA3-256("store-at-idx" | blinded_public_key |
 *             INT_8(replicanum) | INT_8(period_num) )
 *
 * hs_index_out must be large enough to receive DIGEST256_LEN bytes. */
void
hs_build_hs_index(uint64_t replica, const ed25519_public_key_t *blinded_pk,
                  uint64_t period_num, uint8_t *hs_index_out)
{
  crypto_digest_t *digest;

  tor_assert(blinded_pk);
  tor_assert(hs_index_out);

  /* Build hs_index. See construction at top of function comment. */
  digest = crypto_digest256_new(DIGEST_SHA3_256);
  crypto_digest_add_bytes(digest, HS_INDEX_PREFIX, HS_INDEX_PREFIX_LEN);
  crypto_digest_add_bytes(digest, (const char *) blinded_pk->pubkey,
                          ED25519_PUBKEY_LEN);
  crypto_digest_add_bytes(digest, (const char *) &replica, sizeof(replica));
  crypto_digest_add_bytes(digest, (const char *) &period_num,
                          sizeof(period_num));
  crypto_digest_get_digest(digest, (char *) hs_index_out, DIGEST256_LEN);
  crypto_digest_free(digest);
}

/* Build hsdir_index which is used to find the responsible hsdirs. This is the
 * index value that is compare to the hs_index when selecting an HSDir.
 *    SHA3-256("node-idx" | node_identity |
 *             shared_random_value | INT_8(period_num) )
 *
 * hsdir_index_out must be large enough to receive DIGEST256_LEN bytes. */
void
hs_build_hsdir_index(const ed25519_public_key_t *identity_pk,
                     const uint8_t *srv_value, uint64_t period_num,
                     uint8_t *hsdir_index_out)
{
  crypto_digest_t *digest;

  tor_assert(identity_pk);
  tor_assert(srv_value);
  tor_assert(hsdir_index_out);

  /* Build hsdir_index. See construction at top of function comment. */
  digest = crypto_digest256_new(DIGEST_SHA3_256);
  crypto_digest_add_bytes(digest, HSDIR_INDEX_PREFIX, HSDIR_INDEX_PREFIX_LEN);
  crypto_digest_add_bytes(digest, (const char *) identity_pk->pubkey,
                          ED25519_PUBKEY_LEN);
  crypto_digest_add_bytes(digest, (const char *) srv_value, DIGEST256_LEN);
  crypto_digest_add_bytes(digest, (const char *) &period_num,
                          sizeof(period_num));
  crypto_digest_get_digest(digest, (char *) hsdir_index_out, DIGEST256_LEN);
  crypto_digest_free(digest);
}

/* Return a newly allocated buffer containing the current shared random value
 * or if not present, a disaster value is computed using the given time period
 * number. This function can't fail. */
uint8_t *
hs_get_current_srv(uint64_t time_period_num)
{
  uint8_t *sr_value = tor_malloc_zero(DIGEST256_LEN);
  const sr_srv_t *current_srv = sr_get_current();

  if (current_srv) {
    memcpy(sr_value, current_srv->value, sizeof(current_srv->value));
  } else {
    /* Disaster mode. */
    get_disaster_srv(time_period_num, sr_value);
  }
  return sr_value;
}

/* Return a newly allocated buffer containing the previous shared random
 * value or if not present, a disaster value is computed using the given time
 * period number. This function can't fail. */
uint8_t *
hs_get_previous_srv(uint64_t time_period_num)
{
  uint8_t *sr_value = tor_malloc_zero(DIGEST256_LEN);
  const sr_srv_t *previous_srv = sr_get_previous();

  if (previous_srv) {
    memcpy(sr_value, previous_srv->value, sizeof(previous_srv->value));
  } else {
    /* Disaster mode. */
    get_disaster_srv(time_period_num, sr_value);
  }
  return sr_value;
}

/* Initialize the entire HS subsytem. This is called in tor_init() before any
 * torrc options are loaded. Only for >= v3. */
void
hs_init(void)
{
  hs_circuitmap_init();
  hs_service_init();
  hs_cache_init();
}

/* Release and cleanup all memory of the HS subsystem (all version). This is
 * called by tor_free_all(). */
void
hs_free_all(void)
{
  hs_circuitmap_free_all();
  hs_service_free_all();
  hs_cache_free_all();
}

