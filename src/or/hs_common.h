/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_common.h
 * \brief Header file containing common data for the whole HS subsytem.
 **/

#ifndef TOR_HS_COMMON_H
#define TOR_HS_COMMON_H

#include "or.h"

/* Protocol version 2. Use this instead of hardcoding "2" in the code base,
 * this adds a clearer semantic to the value when used. */
#define HS_VERSION_TWO 2
/* Version 3 of the protocol (prop224). */
#define HS_VERSION_THREE 3
/* Earliest and latest version we support. */
#define HS_VERSION_MIN HS_VERSION_TWO
#define HS_VERSION_MAX HS_VERSION_THREE

/** Try to maintain this many intro points per service by default. */
#define NUM_INTRO_POINTS_DEFAULT 3
/** Maximum number of intro points per generic and version 2 service. */
#define NUM_INTRO_POINTS_MAX 10
/** Number of extra intro points we launch if our set of intro nodes is empty.
 * See proposal 155, section 4. */
#define NUM_INTRO_POINTS_EXTRA 2

/** If we can't build our intro circuits, don't retry for this long. */
#define INTRO_CIRC_RETRY_PERIOD (60*5)
/** Don't try to build more than this many circuits before giving up for a
 * while.*/
#define MAX_INTRO_CIRCS_PER_PERIOD 10
/** How many times will a hidden service operator attempt to connect to a
 * requested rendezvous point before giving up? */
#define MAX_REND_FAILURES 1
/** How many seconds should we spend trying to connect to a requested
 * rendezvous point before giving up? */
#define MAX_REND_TIMEOUT 30

/* String prefix for the signature of ESTABLISH_INTRO */
#define ESTABLISH_INTRO_SIG_PREFIX "Tor establish-intro cell v1"

/* The default HS time period length */
#define HS_TIME_PERIOD_LENGTH_DEFAULT 1440 /* 1440 minutes == one day */
/* The minimum time period length as seen in prop224 section [TIME-PERIODS] */
#define HS_TIME_PERIOD_LENGTH_MIN 30 /* minutes */
/* The minimum time period length as seen in prop224 section [TIME-PERIODS] */
#define HS_TIME_PERIOD_LENGTH_MAX (60 * 24 * 10) /* 10 days or 14400 minutes */
/* The time period rotation offset as seen in prop224 section [TIME-PERIODS] */
#define HS_TIME_PERIOD_ROTATION_OFFSET (12 * 60) /* minutes */

/* Prefix of the onion address checksum. */
#define HS_SERVICE_ADDR_CHECKSUM_PREFIX ".onion checksum"
/* Length of the checksum prefix minus the NUL terminated byte. */
#define HS_SERVICE_ADDR_CHECKSUM_PREFIX_LEN \
  (sizeof(HS_SERVICE_ADDR_CHECKSUM_PREFIX) - 1)
/* Length of the resulting checksum of the address. The construction of this
 * checksum looks like:
 *   CHECKSUM = ".onion checksum" || PUBKEY || VERSION
 * where VERSION is 1 byte. This is pre-hashing. */
#define HS_SERVICE_ADDR_CHECKSUM_INPUT_LEN \
  (HS_SERVICE_ADDR_CHECKSUM_PREFIX_LEN + ED25519_PUBKEY_LEN + sizeof(uint8_t))
/* The amount of bytes we use from the address checksum. */
#define HS_SERVICE_ADDR_CHECKSUM_LEN_USED 2
/* Length of the binary encoded service address which is of course before the
 * base32 encoding. Construction is:
 *    PUBKEY || CHECKSUM || VERSION
 * with 1 byte VERSION and 2 bytes CHECKSUM. The following is 35 bytes. */
#define HS_SERVICE_ADDR_LEN \
  (ED25519_PUBKEY_LEN + HS_SERVICE_ADDR_CHECKSUM_LEN_USED + sizeof(uint8_t))
/* Length of 'y' portion of 'y.onion' URL. This is base32 encoded and the
 * length ends up to 56 bytes (not counting the terminated NUL byte.) */
#define HS_SERVICE_ADDR_LEN_BASE32 \
  (CEIL_DIV(HS_SERVICE_ADDR_LEN * 8, 5))

/* Type of authentication key used by an introduction point. */
typedef enum {
  HS_AUTH_KEY_TYPE_LEGACY  = 1,
  HS_AUTH_KEY_TYPE_ED25519 = 2,
} hs_auth_key_type_t;

void hs_init(void);
void hs_free_all(void);

int hs_check_service_private_dir(const char *username, const char *path,
                                 unsigned int dir_group_readable,
                                 unsigned int create);
char *hs_path_from_filename(const char *directory, const char *filename);
void hs_build_address(const ed25519_public_key_t *key, uint8_t version,
                      char *addr_out);
int hs_address_is_valid(const char *address);
int hs_parse_address(const char *address, ed25519_public_key_t *key_out,
                     char *checksum_out, uint8_t *version_out);

void rend_data_free(rend_data_t *data);
rend_data_t *rend_data_dup(const rend_data_t *data);
rend_data_t *rend_data_client_create(const char *onion_address,
                                     const char *desc_id,
                                     const char *cookie,
                                     rend_auth_type_t auth_type);
rend_data_t *rend_data_service_create(const char *onion_address,
                                      const char *pk_digest,
                                      const uint8_t *cookie,
                                      rend_auth_type_t auth_type);
const char *rend_data_get_address(const rend_data_t *rend_data);
const char *rend_data_get_desc_id(const rend_data_t *rend_data,
                                  uint8_t replica, size_t *len_out);
const uint8_t *rend_data_get_pk_digest(const rend_data_t *rend_data,
                                       size_t *len_out);

uint64_t hs_get_next_time_period_num(time_t now);

#ifdef HS_COMMON_PRIVATE

#ifdef TOR_UNIT_TESTS

STATIC uint64_t get_time_period_length(void);
STATIC uint64_t get_time_period_num(time_t now);

#endif /* TOR_UNIT_TESTS */

#endif /* HS_COMMON_PRIVATE */

#endif /* TOR_HS_COMMON_H */

