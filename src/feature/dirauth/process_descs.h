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

// for was_router_added_t.
#include "feature/nodelist/routerlist.h"

#include "src/lib/crypt_ops/crypto_ed25519.h"

struct authdir_config_t;

/** Target of status_by_digest map. */
typedef uint32_t router_status_t;

int add_rsa_fingerprint_to_dir(const char *fp, struct authdir_config_t *list,
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

#if defined(PROCESS_DESCS_PRIVATE) || defined(TOR_UNIT_TESTS)

/*                 1  Historically used to indicate Named */
#define FP_INVALID 2  /**< Believed invalid. */
#define FP_REJECT  4  /**< We will not publish this router. */
/*                 8  Historically used to avoid using this as a dir. */
#define FP_BADEXIT 16 /**< We'll tell clients not to use this as an exit. */
/*                 32 Historically used to indicade Unnamed */

#endif /* defined(TOR_UNIT_TESTS) */

#ifdef TOR_UNIT_TESTS

void authdir_init_fingerprint_list(void);

authdir_config_t *authdir_return_fingerprint_list(void);

#endif /* defined(PROCESS_DESCS_PRIVATE) || defined(TOR_UNIT_TESTS) */

void dirserv_free_fingerprint_list(void);
int dirserv_add_own_fingerprint(crypto_pk_t *pk,
                                const ed25519_public_key_t *edkey);
#ifdef HAVE_MODULE_DIRAUTH
int dirserv_load_fingerprint_file(void);
enum was_router_added_t dirserv_add_multiple_descriptors(
                                     const char *desc, size_t desclen,
                                     uint8_t purpose,
                                     const char *source,
                                     const char **msg);
enum was_router_added_t dirserv_add_descriptor(routerinfo_t *ri,
                                               const char **msg,
                                               const char *source);

int dirserv_would_reject_router(const routerstatus_t *rs,
                                const vote_routerstatus_t *vrs);
int authdir_wants_to_reject_router(routerinfo_t *ri, const char **msg,
                                   int complain,
                                   int *valid_out);
uint32_t dirserv_router_get_status(const routerinfo_t *router,
                                   const char **msg,
                                   int severity);
void dirserv_set_node_flags_from_authoritative_status(node_t *node,
                                                      uint32_t authstatus);
#else /* !(defined(HAVE_MODULE_DIRAUTH)) */
static inline int
dirserv_load_fingerprint_file(void)
{
  return 0;
}
static inline enum was_router_added_t
dirserv_add_multiple_descriptors(const char *desc, size_t desclen,
                                 uint8_t purpose,
                                 const char *source,
                                 const char **msg)
{
  (void)desc;
  (void)desclen;
  (void)purpose;
  (void)source;
  (void)msg;
  return (enum was_router_added_t)0;
}
static inline enum was_router_added_t
dirserv_add_descriptor(routerinfo_t *ri,
                       const char **msg,
                       const char *source)
{
  (void)ri;
  (void)msg;
  (void)source;
  return (enum was_router_added_t)0;
}
static inline int
dirserv_would_reject_router(const routerstatus_t *rs)
{
  (void)rs;
  return 0;
}
static inline int
authdir_wants_to_reject_router(routerinfo_t *ri, const char **msg,
                               int complain,
                               int *valid_out)
{
  (void)ri;
  (void)msg;
  (void)complain;
  (void)valid_out;
  return 0;
}
static inline int
dirserv_add_own_fingerprint(crypto_pk_t *pk, const ed25519_public_key_t *edkey)
{
  (void)pk;
  (void)edkey;
  return 0;
}
static inline uint32_t
dirserv_router_get_status(const routerinfo_t *router,
                          const char **msg,
                          int severity)
{
  (void)router;
  (void)msg;
  (void)severity;
  return 0;
}
static inline void
dirserv_set_node_flags_from_authoritative_status(node_t *node,
                                                 uint32_t authstatus)
{
  (void)node;
  (void)authstatus;
}
#endif /* defined(HAVE_MODULE_DIRAUTH) */

#ifdef TOR_UNIT_TESTS
STATIC int dirserv_router_has_valid_address(routerinfo_t *ri);
#endif /* defined(TOR_UNIT_TESTS) */

#endif /* !defined(TOR_RECV_UPLOADS_H) */
