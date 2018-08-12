/* Copyright (c) 2010-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define TORTLS_PRIVATE
#define TOR_X509_PRIVATE
#define LOG_PRIVATE
#include "orconfig.h"

#ifdef _WIN32
#include <winsock2.h>
#endif
#include <math.h>
#include <stddef.h>

#include "lib/cc/compat_compiler.h"

#include "core/or/or.h"
#include "lib/log/log.h"
#include "app/config/config.h"
#include "lib/crypt_ops/compat_openssl.h"
#include "lib/tls/x509.h"
#include "lib/tls/tortls.h"
#include "lib/tls/tortls_st.h"
#include "lib/tls/tortls_internal.h"
#include "app/config/or_state_st.h"

#include "test/test.h"
#include "test/log_test_helpers.h"

#include "tinytest.h"

static void
test_tortls_errno_to_tls_error(void *data)
{
  (void) data;
  tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(ECONNRESET)),OP_EQ,
            TOR_TLS_ERROR_CONNRESET);
  tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(ETIMEDOUT)),OP_EQ,
            TOR_TLS_ERROR_TIMEOUT);
  tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(EHOSTUNREACH)),OP_EQ,
            TOR_TLS_ERROR_NO_ROUTE);
  tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(ENETUNREACH)),OP_EQ,
            TOR_TLS_ERROR_NO_ROUTE);
  tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(ECONNREFUSED)),OP_EQ,
            TOR_TLS_ERROR_CONNREFUSED);
  tt_int_op(tor_errno_to_tls_error(0),OP_EQ,TOR_TLS_ERROR_MISC);
 done:
  (void)1;
}

static void
test_tortls_err_to_string(void *data)
{
  (void) data;
  tt_str_op(tor_tls_err_to_string(1),OP_EQ,"[Not an error.]");
  tt_str_op(tor_tls_err_to_string(TOR_TLS_ERROR_MISC),OP_EQ,"misc error");
  tt_str_op(tor_tls_err_to_string(TOR_TLS_ERROR_IO),OP_EQ,"unexpected close");
  tt_str_op(tor_tls_err_to_string(TOR_TLS_ERROR_CONNREFUSED),OP_EQ,
            "connection refused");
  tt_str_op(tor_tls_err_to_string(TOR_TLS_ERROR_CONNRESET),OP_EQ,
            "connection reset");
  tt_str_op(tor_tls_err_to_string(TOR_TLS_ERROR_NO_ROUTE),OP_EQ,
            "host unreachable");
  tt_str_op(tor_tls_err_to_string(TOR_TLS_ERROR_TIMEOUT),OP_EQ,
            "connection timed out");
  tt_str_op(tor_tls_err_to_string(TOR_TLS_CLOSE),OP_EQ,"closed");
  tt_str_op(tor_tls_err_to_string(TOR_TLS_WANTREAD),OP_EQ,"want to read");
  tt_str_op(tor_tls_err_to_string(TOR_TLS_WANTWRITE),OP_EQ,"want to write");
  tt_str_op(tor_tls_err_to_string(-100),OP_EQ,"(unknown error code)");
 done:
  (void)1;
}

static int
mock_tls_cert_matches_key(const tor_tls_t *tls, const tor_x509_cert_t *cert)
{
  (void) tls;
  (void) cert; // XXXX look at this.
  return 1;
}

static void
test_tortls_tor_tls_get_error(void *data)
{
  (void) data;
  MOCK(tor_tls_cert_matches_key, mock_tls_cert_matches_key);
  crypto_pk_t *key1 = NULL, *key2 = NULL;
  key1 = pk_generate(2);
  key2 = pk_generate(3);

  tor_tls_t *tls = NULL;
  tt_int_op(tor_tls_context_init(TOR_TLS_CTX_IS_PUBLIC_SERVER,
                                 key1, key2, 86400), OP_EQ, 0);
  tls = tor_tls_new(-1, 0);
  setup_capture_of_logs(LOG_WARN);
  tor_tls_get_error(tls, 0, 0,
                    (const char *)"in unit test", LOG_WARN, LD_GENERAL);
  expect_single_log_msg_containing("unexpected close while in unit test");

 done:
  UNMOCK(tor_tls_cert_matches_key);
  NS_UNMOCK(logv);
  crypto_pk_free(key1);
  crypto_pk_free(key2);
  tor_tls_free(tls);
}

static void
test_tortls_x509_cert_get_id_digests(void *ignored)
{
  (void)ignored;
  tor_x509_cert_t *cert;
  common_digests_t *d;
  const common_digests_t *res;
  cert = tor_malloc_zero(sizeof(tor_x509_cert_t));
  d = tor_malloc_zero(sizeof(common_digests_t));
  d->d[0][0] = 42;

  res = tor_x509_cert_get_id_digests(cert);
  tt_assert(!res);

  cert->pkey_digests_set = 1;
  cert->pkey_digests = *d;
  res = tor_x509_cert_get_id_digests(cert);
  tt_int_op(res->d[0][0], OP_EQ, 42);

 done:
  tor_free(cert);
  tor_free(d);
}

static void
test_tortls_get_my_certs(void *ignored)
{
  (void)ignored;
  int ret;
  tor_tls_context_t *ctx;
  const tor_x509_cert_t *link_cert_out = NULL;
  const tor_x509_cert_t *id_cert_out = NULL;

  ctx = tor_malloc_zero(sizeof(tor_tls_context_t));

  client_tls_context = NULL;
  ret = tor_tls_get_my_certs(0, NULL, NULL);
  tt_int_op(ret, OP_EQ, -1);

  server_tls_context = NULL;
  ret = tor_tls_get_my_certs(1, NULL, NULL);
  tt_int_op(ret, OP_EQ, -1);

  client_tls_context = ctx;
  ret = tor_tls_get_my_certs(0, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  client_tls_context = ctx;
  ret = tor_tls_get_my_certs(0, &link_cert_out, &id_cert_out);
  tt_int_op(ret, OP_EQ, 0);

  server_tls_context = ctx;
  ret = tor_tls_get_my_certs(1, &link_cert_out, &id_cert_out);
  tt_int_op(ret, OP_EQ, 0);

 done:
  (void)1;
}

static void
test_tortls_get_forced_write_size(void *ignored)
{
  (void)ignored;
  long ret;
  tor_tls_t *tls;

  tls = tor_malloc_zero(sizeof(tor_tls_t));

  tls->wantwrite_n = 43;
  ret = tor_tls_get_forced_write_size(tls);
  tt_int_op(ret, OP_EQ, 43);

 done:
  tor_free(tls);
}

static void
test_tortls_used_v1_handshake(void *ignored)
{
  (void)ignored;
  int ret;
  tor_tls_t *tls;
  tls = tor_malloc_zero(sizeof(tor_tls_t));

  // These tests assume both V2 handshake server and client are enabled
  tls->wasV2Handshake = 0;
  ret = tor_tls_used_v1_handshake(tls);
  tt_int_op(ret, OP_EQ, 1);

  tls->wasV2Handshake = 1;
  ret = tor_tls_used_v1_handshake(tls);
  tt_int_op(ret, OP_EQ, 0);

 done:
  tor_free(tls);
}

static void
test_tortls_get_num_server_handshakes(void *ignored)
{
  (void)ignored;
  int ret;
  tor_tls_t *tls;

  tls = tor_malloc_zero(sizeof(tor_tls_t));

  tls->server_handshake_count = 3;
  ret = tor_tls_get_num_server_handshakes(tls);
  tt_int_op(ret, OP_EQ, 3);

 done:
  tor_free(tls);
}

static void
test_tortls_server_got_renegotiate(void *ignored)
{
  (void)ignored;
  int ret;
  tor_tls_t *tls;

  tls = tor_malloc_zero(sizeof(tor_tls_t));

  tls->got_renegotiate = 1;
  ret = tor_tls_server_got_renegotiate(tls);
  tt_int_op(ret, OP_EQ, 1);

 done:
  tor_free(tls);
}

static void
test_tortls_evaluate_ecgroup_for_tls(void *ignored)
{
  (void)ignored;
  int ret;

  ret = evaluate_ecgroup_for_tls(NULL);
  tt_int_op(ret, OP_EQ, 1);

  ret = evaluate_ecgroup_for_tls("foobar");
  tt_int_op(ret, OP_EQ, 0);

  ret = evaluate_ecgroup_for_tls("P256");
  tt_int_op(ret, OP_EQ, 1);

  ret = evaluate_ecgroup_for_tls("P224");
  //  tt_int_op(ret, OP_EQ, 1); This varies between machines
  tt_assert(ret == 0 || ret == 1);

 done:
  (void)0;
}

#define LOCAL_TEST_CASE(name, flags)                            \
  { #name, test_tortls_##name, (flags|TT_FORK), NULL, NULL }

struct testcase_t tortls_tests[] = {
  LOCAL_TEST_CASE(errno_to_tls_error, 0),
  LOCAL_TEST_CASE(err_to_string, 0),
  LOCAL_TEST_CASE(tor_tls_get_error, 0),
  LOCAL_TEST_CASE(x509_cert_get_id_digests, 0),
  LOCAL_TEST_CASE(get_my_certs, TT_FORK),
  LOCAL_TEST_CASE(get_forced_write_size, 0),
  LOCAL_TEST_CASE(used_v1_handshake, TT_FORK),
  LOCAL_TEST_CASE(get_num_server_handshakes, 0),
  LOCAL_TEST_CASE(server_got_renegotiate, 0),
  LOCAL_TEST_CASE(evaluate_ecgroup_for_tls, 0),
  END_OF_TESTCASES
};
