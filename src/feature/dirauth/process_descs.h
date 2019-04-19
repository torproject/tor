/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file process_descs.h
 * \brief Header file for process_descs.c.
 **/

#ifndef TOR_RECV_UPLOADS_H
#define TOR_RECV_UPLOADS_H

#include "src/lib/crypt_ops/crypto_ed25519.h"

struct authdir_config_t;

/** Target of status_by_digest map. */
typedef uint32_t router_status_t;

int add_fingerprint_to_dir(const char *fp, struct authdir_config_t *list,
                           router_status_t add_status);

int add_ed25519_to_dir(const ed25519_public_key_t *edkey,
                       struct authdir_config_t *list,
                       router_status_t add_status);

/** List of nickname-\>identity fingerprint mappings for all the routers
 * that we name.  Used to prevent router impersonation. */
typedef struct authdir_config_t {
  strmap_t *fp_by_name; /**< Map from lc nickname to fingerprint. */
  digestmap_t *status_by_digest; /**< Map from digest to router_status_t. */
  digest256map_t *status_by_digest256; /**< Map from digest256 to
                                        * router_status_t. */
} authdir_config_t;

#ifdef TOR_UNIT_TESTS

void authdir_init_fingerprint_list(void);

authdir_config_t *authdir_return_fingerprint_list(void);

#endif /* defined(TOR_UNIT_TESTS) */

int dirserv_load_fingerprint_file(void);
void dirserv_free_fingerprint_list(void);
int dirserv_add_own_fingerprint(crypto_pk_t *pk);

enum was_router_added_t dirserv_add_multiple_descriptors(
                                     const char *desc, size_t desclen,
                                     uint8_t purpose,
                                     const char *source,
                                     const char **msg);
enum was_router_added_t dirserv_add_descriptor(routerinfo_t *ri,
                                               const char **msg,
                                               const char *source);

int authdir_wants_to_reject_router(routerinfo_t *ri, const char **msg,
                                   int complain,
                                   int *valid_out);
uint32_t dirserv_router_get_status(const routerinfo_t *router,
                                   const char **msg,
                                   int severity);
void dirserv_set_node_flags_from_authoritative_status(node_t *node,
                                                      uint32_t authstatus);

int dirserv_would_reject_router(const routerstatus_t *rs);

#endif
