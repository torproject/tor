/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file router.h
 * \brief Header file for router.c.
 **/

#ifndef TOR_ROUTER_H
#define TOR_ROUTER_H

#include "lib/testsupport/testsupport.h"

struct curve25519_keypair_t;
struct ed25519_keypair_t;

int router_initialize_tls_context(void);
int init_keys_client(void);
void set_client_identity_key(crypto_pk_t *k);
crypto_pk_t *get_tlsclient_identity_key(void);
int client_identity_key_is_set(void);

#ifdef HAVE_MODULE_RELAY

#define TOR_ROUTERINFO_ERROR_NO_EXT_ADDR     (-1)
#define TOR_ROUTERINFO_ERROR_CANNOT_PARSE    (-2)
#define TOR_ROUTERINFO_ERROR_NOT_A_SERVER    (-3)
#define TOR_ROUTERINFO_ERROR_DIGEST_FAILED   (-4)
#define TOR_ROUTERINFO_ERROR_CANNOT_GENERATE (-5)
#define TOR_ROUTERINFO_ERROR_DESC_REBUILDING (-6)
#define TOR_ROUTERINFO_ERROR_INTERNAL_BUG    (-7)

int init_keys(void);

MOCK_DECL(crypto_pk_t *,get_onion_key,(void));
time_t get_onion_key_set_at(void);
void set_server_identity_key(crypto_pk_t *k);
/* Some compilers are clever enough to know that when relay mode is disabled,
 * this function never returns. */
MOCK_DECL(crypto_pk_t *,get_server_identity_key,(void));
int server_identity_key_is_set(void);
MOCK_DECL(authority_cert_t *, get_my_v3_authority_cert, (void));
crypto_pk_t *get_my_v3_authority_signing_key(void);
authority_cert_t *get_my_v3_legacy_cert(void);
crypto_pk_t *get_my_v3_legacy_signing_key(void);
void dup_onion_keys(crypto_pk_t **key, crypto_pk_t **last);
void expire_old_onion_keys(void);
void rotate_onion_key(void);
void v3_authority_check_key_expiry(void);
int get_onion_key_lifetime(void);
int get_onion_key_grace_period(void);

void router_set_rsa_onion_pkey(const crypto_pk_t *pk, char **onion_pkey_out,
                               size_t *onion_pkey_len);

di_digest256_map_t *construct_ntor_key_map(void);
void ntor_key_map_free_(di_digest256_map_t *map);
#define ntor_key_map_free(map) \
  FREE_AND_NULL(di_digest256_map_t, ntor_key_map_free_, (map))

uint16_t router_get_active_listener_port_by_type_af(int listener_type,
                                                    sa_family_t family);
uint16_t router_get_advertised_or_port(const or_options_t *options);
void router_get_advertised_ipv6_or_ap(const or_options_t *options,
                                      tor_addr_port_t *ipv6_ap_out);
uint16_t router_get_advertised_or_port_by_af(const or_options_t *options,
                                             sa_family_t family);
uint16_t router_get_advertised_dir_port(const or_options_t *options,
                                        uint16_t dirport);

int router_should_advertise_dirport(const or_options_t *options,
                                    uint16_t dir_port);
int router_should_advertise_begindir(const or_options_t *options,
                                     int supports_tunnelled_dir_requests);

void consider_publishable_server(int force);
int should_refuse_unknown_exits(const or_options_t *options);

int router_has_bandwidth_to_be_dirserver(const or_options_t *options);
void router_new_address_suggestion(const char *suggestion,
                                   const dir_connection_t *d_conn);
int router_compare_to_my_exit_policy(const tor_addr_t *addr, uint16_t port);
MOCK_DECL(int, router_my_exit_policy_is_reject_star,(void));
int router_digest_is_me(const char *digest);
const uint8_t *router_get_my_id_digest(void);
int router_extrainfo_digest_is_me(const char *digest);
int router_is_me(const routerinfo_t *router);
MOCK_DECL(int,router_pick_published_address,(const or_options_t *options,
                                             uint32_t *addr,
                                             int cache_only));
void check_descriptor_bandwidth_changed(time_t now);
void check_descriptor_ipaddress_changed(time_t now);
const char *routerinfo_err_to_string(int err);
int routerinfo_err_is_transient(int err);

void router_free_all(void);

MOCK_DECL(const struct curve25519_keypair_t *,
                 get_current_curve25519_keypair,(void));

#ifdef ROUTER_PRIVATE
/* Used only by router.c and the unit tests */
STATIC int router_write_fingerprint(int hashed);

#ifdef TOR_UNIT_TESTS
void set_server_identity_key_digest_testing(const uint8_t *digest);
#endif /* defined(TOR_UNIT_TESTS) */

#endif /* defined(ROUTER_PRIVATE) */

#else /* !defined(HAVE_RELAY_MODE) */

#define IGNORE1(a)                              \
  ((void)(a))
#define IGNORE1_RET(a, r)                       \
  (IGNORE1(a), (r))
#define IGNORE2(a,b)                            \
  ((void)(a), (void)(b))
#define IGNORE2_RET(a,b, r)                     \
  (IGNORE2((a),(b)), (r))
#define IGNORE3(a,b,c)                          \
  ((void)(a), (void)(b), (void)(c))
#define IGNORE3_RET(a,b,c, r)                   \
  (IGNORE3((a),(b),(c)), (r))

#define get_server_identity_key()(tor_abort_(),NULL)
#define dup_onion_keys(key,last) \
  (*(key)=NULL, *(last)=NULL)
#define expire_old_onion_keys() \
  STMT_NIL
#define rotate_onion_key() \
  STMT_NIL

#define construct_ntor_key_map() \
  tor_malloc(1)
#define ntor_key_map_free(map) \
  tor_free(map)

#define router_digest_is_me(digest) \
  IGNORE1_RET((digest), 0)
#define router_get_my_id_digest()               \
  ("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"   \
   "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
#define router_extrainfo_digest_is_me(digest) \
  IGNORE1_RET((digest), 0)
#define router_is_me(r)                         \
  IGNORE1_RET((r), 0)
#define server_identity_key_is_set() \
  (0)

#define router_get_advertised_or_port(opts) \
  IGNORE1_RET((opts), 0)
#define router_get_advertised_or_port_by_af(opts, af) \
  IGNORE2_RET((opts), (af), 0)
#define router_get_advertised_dir_port(opts, port) \
  IGNORE2_RET((opts), (port), 0)
#define router_get_active_listener_port_by_type_af(lt,fam) \
  IGNORE2_RET((lt), (fam), 0)

#define router_compare_to_my_exit_policy(addr, port) \
  IGNORE2_RET((addr), (port), -1)
#define router_my_exit_policy_is_reject_star() \
  (1)

#define should_refuse_unknown_exits(opts) \
  IGNORE1_RET((opts), 1)

/* TODO: These should be disabled by v3auth mode, not relay mode. */
#define get_my_v3_authority_cert()              \
  NULL
#define get_my_v3_authority_signing_key()       \
  NULL
#define get_my_v3_legacy_cert()                 \
  NULL
#define get_my_v3_legacy_signing_key()          \
  NULL

#define routerinfo_err_is_transient(e)          \
  IGNORE1_RET((e), 0)
#define routerinfo_err_to_string(e)             \
  IGNORE1_RET((e), "Tor was compiled without relay support")

#define router_pick_published_address(opt, addr, cache) \
  IGNORE3_RET((opt), (addr), (cache), -1)

#define router_new_address_suggestion(s, d) \
  IGNORE2((s),(d))

#define init_keys() \
  init_keys_client()

#endif /* defined(HAVE_RELAY_MODE) */

#endif /* !defined(TOR_ROUTER_H) */
