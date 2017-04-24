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
#include "hs_common.h"
#include "rendcommon.h"

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
STATIC uint64_t
get_time_period_num(time_t now)
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
  return get_time_period_num(now) + 1;
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

