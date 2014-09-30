/* Copyright (c) 2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_ROUTERKEYS_H
#define TOR_ROUTERKEYS_H

#include "crypto_ed25519.h"

#define INIT_ED_KEY_CREATE                      (1u<<0)
#define INIT_ED_KEY_REPLACE                     (1u<<1)
#define INIT_ED_KEY_SPLIT                       (1u<<2)
#define INIT_ED_KEY_MISSING_SECRET_OK           (1u<<3)
#define INIT_ED_KEY_NEEDCERT                    (1u<<4)
#define INIT_ED_KEY_EXTRA_STRONG                (1u<<5)
#define INIT_ED_KEY_INCLUDE_SIGNING_KEY_IN_CERT (1u<<6)

struct tor_cert_st;
ed25519_keypair_t *ed_key_init_from_file(const char *fname, uint32_t flags,
                                         int severity,
                                         const ed25519_keypair_t *signing_key,
                                         time_t now,
                                         time_t lifetime,
                                         uint8_t cert_type,
                                         struct tor_cert_st **cert_out);
ed25519_keypair_t *ed_key_new(const ed25519_keypair_t *signing_key,
                              uint32_t flags,
                              time_t now,
                              time_t lifetime,
                              uint8_t cert_type,
                              struct tor_cert_st **cert_out);
const ed25519_public_key_t *get_master_identity_key(void);
const ed25519_keypair_t *get_master_signing_keypair(void);
const struct tor_cert_st *get_master_signing_key_cert(void);

const ed25519_keypair_t *get_current_link_keypair(void);
const ed25519_keypair_t *get_current_auth_keypair(void);
const struct tor_cert_st *get_current_link_key_cert(void);
const struct tor_cert_st *get_current_auth_key_cert(void);

int load_ed_keys(const or_options_t *options, time_t now);
void routerkeys_free_all(void);

#endif

