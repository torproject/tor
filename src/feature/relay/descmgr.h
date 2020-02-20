/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file descmgr.h
 * @brief Header for feature/relay/descmgr.c
 **/

#ifndef TOR_FEATURE_RELAY_MAKEDESC_H
#define TOR_FEATURE_RELAY_MAKEDESC_H

#include "lib/testsupport/testsupport.h"

struct curve25519_keypair_t;
struct ed25519_keypair_t;

#ifdef HAVE_MODULE_RELAY

char *router_dump_exit_policy_to_string(const routerinfo_t *router,
                                         int include_ipv4,
                                         int include_ipv6);

void router_upload_dir_desc_to_dirservers(int force);
void mark_my_descriptor_dirty_if_too_old(time_t now);
void mark_my_descriptor_dirty(const char *reason);

int router_build_fresh_descriptor(routerinfo_t **r, extrainfo_t **e);
int router_rebuild_descriptor(int force);

MOCK_DECL(const routerinfo_t *, router_get_my_routerinfo, (void));
MOCK_DECL(const routerinfo_t *, router_get_my_routerinfo_with_err,(int *err));
extrainfo_t *router_get_my_extrainfo(void);
const char *router_get_my_descriptor(void);
const char *router_get_descriptor_gen_reason(void);

void router_reset_warnings(void);
void makedesc_free_all(void);

#ifdef MAKEDESC_PRIVATE
#ifdef TOR_UNIT_TESTS
extern time_t desc_clean_since;
extern const char *desc_dirty_reason;
#endif
STATIC char *router_dump_router_to_string(routerinfo_t *router,
                             const crypto_pk_t *ident_key,
                             const crypto_pk_t *tap_key,
                             const struct curve25519_keypair_t *ntor_keypair,
                             const struct ed25519_keypair_t *signing_keypair);
STATIC int extrainfo_dump_to_string(char **s, extrainfo_t *extrainfo,
                             crypto_pk_t *ident_key,
                             const struct ed25519_keypair_t *signing_keypair);
STATIC void get_platform_str(char *platform, size_t len);
STATIC smartlist_t *get_my_declared_family(const or_options_t *options);
MOCK_DECL(STATIC int,
              router_build_fresh_unsigned_routerinfo,(routerinfo_t **ri_out));
STATIC extrainfo_t *router_build_fresh_signed_extrainfo(
                                                      const routerinfo_t *ri);
STATIC void router_update_routerinfo_from_extrainfo(routerinfo_t *ri,
                                                    const extrainfo_t *ei);
STATIC int router_dump_and_sign_routerinfo_descriptor_body(routerinfo_t *ri);
#endif

#else /* !defined(HAVE_MODULE_RELAY) */

#define router_dump_exit_policy_to_string(r, i4, i6)\
  ((void)(r), (void)(i4), (void)(i6), NULL)

#define router_upload_dir_desc_to_dirservers(force) \
  ((void)(force))
#define mark_my_descriptor_dirty_if_too_old(now) \
  ((void)(now))
#define mark_my_descriptor_dirty(reason) \
  ((void)(reason))

#define router_build_fresh_descriptor(r,e) \
  (*(r)=NULL, *(e)=NULL, 0)
#define router_rebuild_descriptor(force) \
  ((void)force, 0)
#define router_get_my_routerinfo() \
  NULL
#define router_get_my_routerinfo_with_err(errp) \
  (*(errp)=0, NULL)
#define router_get_my_extrainfo() \
  NULL
#define router_get_my_descriptor() \
  NULL
#define router_get_descriptor_gen_reason() \
  NULL
#define router_reset_warnings() \
  STMT_NIL

#endif /* defined(HAVE_MODULE_RELAY) */

#endif /* !defined(TOR_FEATURE_RELAY_MAKEDESC_H) */
