/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file clientkey.c
 * @brief "Client"-related key management operations.
 *
 * These functions are used by clients and relay code paths alike, in spite of
 * residing in feature/relay.  They should be refatored, moved, made
 * relay-only, or removed entirely, but for now, they are residing here
 * pending analysis.
 **/

#include "orconfig.h"
#include "core/or/or.h"
#include "feature/relay/clientkey.h"

#include "app/config/config.h"
#include "feature/relay/router.h"
#include "feature/relay/routermode.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/tls/tortls.h"

/** Private client "identity key": used to sign bridges' and clients'
 * outbound TLS certificates. Regenerated on startup and on IP address
 * change. */
static crypto_pk_t *client_identitykey=NULL;

int
init_keys_client(void)
{
  crypto_pk_t *prkey;
  if (init_keys_common() < 0)
    return -1;

  if (!(prkey = crypto_pk_new()))
    return -1;
  if (crypto_pk_generate_key(prkey)) {
    crypto_pk_free(prkey);
    return -1;
  }
  set_client_identity_key(prkey);
  /* Create a TLS context. */
  if (router_initialize_tls_context() < 0) {
    log_err(LD_GENERAL,"Error creating TLS context for Tor client.");
    return -1;
  }
  return 0;
}

/** Set the current client identity key to <b>k</b>.
 */
void
set_client_identity_key(crypto_pk_t *k)
{
  crypto_pk_free(client_identitykey);
  client_identitykey = k;
}

/** Returns the current client identity key for use on outgoing TLS
 * connections; requires that the key has been set.
 */
crypto_pk_t *
get_tlsclient_identity_key(void)
{
  tor_assert(client_identitykey);
  return client_identitykey;
}

/** Return true iff the client identity key has been set. */
int
client_identity_key_is_set(void)
{
  return client_identitykey != NULL;
}

/** Set up Tor's TLS contexts, based on our configuration and keys. Return 0
 * on success, and -1 on failure. */
int
router_initialize_tls_context(void)
{
  unsigned int flags = 0;
  const or_options_t *options = get_options();
  int lifetime = options->SSLKeyLifetime;
  if (public_server_mode(options))
    flags |= TOR_TLS_CTX_IS_PUBLIC_SERVER;
  if (!lifetime) { /* we should guess a good ssl cert lifetime */

    /* choose between 5 and 365 days, and round to the day */
    unsigned int five_days = 5*24*3600;
    unsigned int one_year = 365*24*3600;
    lifetime = crypto_rand_int_range(five_days, one_year);
    lifetime -= lifetime % (24*3600);

    if (crypto_rand_int(2)) {
      /* Half the time we expire at midnight, and half the time we expire
       * one second before midnight. (Some CAs wobble their expiry times a
       * bit in practice, perhaps to reduce collision attacks; see ticket
       * 8443 for details about observed certs in the wild.) */
      lifetime--;
    }
  }

  /* It's ok to pass lifetime in as an unsigned int, since
   * config_parse_interval() checked it. */
  return tor_tls_context_init(flags,
                              get_tlsclient_identity_key(),
                              server_mode(options) ?
                              get_server_identity_key() : NULL,
                              (unsigned int)lifetime);
}

void
clientkey_free_all(void)
{
  crypto_pk_free(client_identitykey);
}
