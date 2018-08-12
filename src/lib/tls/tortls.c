/* Copyright (c) 2003, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define TORTLS_PRIVATE
#include "lib/tls/x509.h"
#include "lib/tls/tortls.h"
#include "lib/tls/tortls_st.h"
#include "lib/tls/tortls_internal.h"
#include "lib/log/util_bug.h"
#include "lib/intmath/cmp.h"

/** Global TLS contexts. We keep them here because nobody else needs
 * to touch them.
 *
 * @{ */
STATIC tor_tls_context_t *server_tls_context = NULL;
STATIC tor_tls_context_t *client_tls_context = NULL;
/**@}*/

/**
 * Return the appropriate TLS context.
 */
tor_tls_context_t *
tor_tls_context_get(int is_server)
{
  return is_server ? server_tls_context : client_tls_context;
}

/** Increase the reference count of <b>ctx</b>. */
void
tor_tls_context_incref(tor_tls_context_t *ctx)
{
  ++ctx->refcnt;
}

/** Free all global TLS structures. */
void
tor_tls_free_all(void)
{
  check_no_tls_errors();

  if (server_tls_context) {
    tor_tls_context_t *ctx = server_tls_context;
    server_tls_context = NULL;
    tor_tls_context_decref(ctx);
  }
  if (client_tls_context) {
    tor_tls_context_t *ctx = client_tls_context;
    client_tls_context = NULL;
    tor_tls_context_decref(ctx);
  }
}

/** Given a TOR_TLS_* error code, return a string equivalent. */
const char *
tor_tls_err_to_string(int err)
{
  if (err >= 0)
    return "[Not an error.]";
  switch (err) {
    case TOR_TLS_ERROR_MISC: return "misc error";
    case TOR_TLS_ERROR_IO: return "unexpected close";
    case TOR_TLS_ERROR_CONNREFUSED: return "connection refused";
    case TOR_TLS_ERROR_CONNRESET: return "connection reset";
    case TOR_TLS_ERROR_NO_ROUTE: return "host unreachable";
    case TOR_TLS_ERROR_TIMEOUT: return "connection timed out";
    case TOR_TLS_CLOSE: return "closed";
    case TOR_TLS_WANTREAD: return "want to read";
    case TOR_TLS_WANTWRITE: return "want to write";
    default: return "(unknown error code)";
  }
}

/** Create new global client and server TLS contexts.
 *
 * If <b>server_identity</b> is NULL, this will not generate a server
 * TLS context. If TOR_TLS_CTX_IS_PUBLIC_SERVER is set in <b>flags</b>, use
 * the same TLS context for incoming and outgoing connections, and
 * ignore <b>client_identity</b>. If one of TOR_TLS_CTX_USE_ECDHE_P{224,256}
 * is set in <b>flags</b>, use that ECDHE group if possible; otherwise use
 * the default ECDHE group. */
int
tor_tls_context_init(unsigned flags,
                     crypto_pk_t *client_identity,
                     crypto_pk_t *server_identity,
                     unsigned int key_lifetime)
{
  int rv1 = 0;
  int rv2 = 0;
  const int is_public_server = flags & TOR_TLS_CTX_IS_PUBLIC_SERVER;
  check_no_tls_errors();

  if (is_public_server) {
    tor_tls_context_t *new_ctx;
    tor_tls_context_t *old_ctx;

    tor_assert(server_identity != NULL);

    rv1 = tor_tls_context_init_one(&server_tls_context,
                                   server_identity,
                                   key_lifetime, flags, 0);

    if (rv1 >= 0) {
      new_ctx = server_tls_context;
      tor_tls_context_incref(new_ctx);
      old_ctx = client_tls_context;
      client_tls_context = new_ctx;

      if (old_ctx != NULL) {
        tor_tls_context_decref(old_ctx);
      }
    }
  } else {
    if (server_identity != NULL) {
      rv1 = tor_tls_context_init_one(&server_tls_context,
                                     server_identity,
                                     key_lifetime,
                                     flags,
                                     0);
    } else {
      tor_tls_context_t *old_ctx = server_tls_context;
      server_tls_context = NULL;

      if (old_ctx != NULL) {
        tor_tls_context_decref(old_ctx);
      }
    }

    rv2 = tor_tls_context_init_one(&client_tls_context,
                                   client_identity,
                                   key_lifetime,
                                   flags,
                                   1);
  }

  tls_log_errors(NULL, LOG_WARN, LD_CRYPTO, "constructing a TLS context");
  return MIN(rv1, rv2);
}

/** Make future log messages about <b>tls</b> display the address
 * <b>address</b>.
 */
void
tor_tls_set_logged_address(tor_tls_t *tls, const char *address)
{
  tor_assert(tls);
  tor_free(tls->address);
  tls->address = tor_strdup(address);
}

/** Return whether this tls initiated the connect (client) or
 * received it (server). */
int
tor_tls_is_server(tor_tls_t *tls)
{
  tor_assert(tls);
  return tls->isServer;
}
