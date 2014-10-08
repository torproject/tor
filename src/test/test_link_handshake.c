/* Copyright (c) 2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

#define CHANNELTLS_PRIVATE
#define CONNECTION_PRIVATE
#define TOR_CHANNEL_INTERNAL_
#include "or.h"
#include "config.h"
#include "connection.h"
#include "connection_or.h"
#include "channeltls.h"
#include "link_handshake.h"

#include "test.h"

var_cell_t *mock_got_var_cell = NULL;

static void
mock_write_var_cell(const var_cell_t *vc, or_connection_t *conn)
{
  (void)conn;

  var_cell_t *newcell = var_cell_new(vc->payload_len);
  memcpy(newcell, vc, sizeof(var_cell_t));
  memcpy(newcell->payload, vc->payload, vc->payload_len);

  mock_got_var_cell = newcell;
}
static int
mock_tls_cert_matches_key(const tor_tls_t *tls, const tor_x509_cert_t *cert)
{
  (void) tls;
  (void) cert; // XXXX look at this.
  return 1;
}

static int mock_send_netinfo_called = 0;
static int
mock_send_netinfo(or_connection_t *conn)
{
  (void) conn;
  ++mock_send_netinfo_called;// XXX check_this
  return 0;
}

static int mock_close_called = 0;
static void
mock_close_for_err(or_connection_t *orconn, int flush)
{
  (void)orconn;
  (void)flush;
  ++mock_close_called;
}

static int mock_send_authenticate_called = 0;
static int
mock_send_authenticate(or_connection_t *conn, int type)
{
  (void) conn;
  (void) type;
  ++mock_send_authenticate_called;// XXX check_this
  return 0;
}

/* Test good certs cells */
static void
test_link_handshake_certs_ok(void *arg)
{
  (void) arg;

  or_connection_t *c1 = or_connection_new(CONN_TYPE_OR, AF_INET);
  or_connection_t *c2 = or_connection_new(CONN_TYPE_OR, AF_INET);
  var_cell_t *cell1 = NULL, *cell2 = NULL;
  certs_cell_t *cc1 = NULL, *cc2 = NULL;
  channel_tls_t *chan1 = NULL, *chan2 = NULL;
  crypto_pk_t *key1 = NULL, *key2 = NULL;

  scheduler_init();

  MOCK(tor_tls_cert_matches_key, mock_tls_cert_matches_key);
  MOCK(connection_or_write_var_cell_to_buf, mock_write_var_cell);
  MOCK(connection_or_send_netinfo, mock_send_netinfo);

  key1 = pk_generate(2);
  key2 = pk_generate(3);

  /* We need to make sure that our TLS certificates are set up before we can
   * actually generate a CERTS cell.
   */
  tt_int_op(tor_tls_context_init(TOR_TLS_CTX_IS_PUBLIC_SERVER,
                                 key1, key2, 86400), ==, 0);

  c1->base_.state = OR_CONN_STATE_OR_HANDSHAKING_V3;
  c1->link_proto = 3;
  tt_int_op(connection_init_or_handshake_state(c1, 1), ==, 0);

  c2->base_.state = OR_CONN_STATE_OR_HANDSHAKING_V3;
  c2->link_proto = 3;
  tt_int_op(connection_init_or_handshake_state(c2, 0), ==, 0);

  tt_int_op(0, ==, connection_or_send_certs_cell(c1));
  tt_assert(mock_got_var_cell);
  cell1 = mock_got_var_cell;

  tt_int_op(0, ==, connection_or_send_certs_cell(c2));
  tt_assert(mock_got_var_cell);
  cell2 = mock_got_var_cell;

  tt_int_op(cell1->command, ==, CELL_CERTS);
  tt_int_op(cell1->payload_len, >, 1);

  tt_int_op(cell2->command, ==, CELL_CERTS);
  tt_int_op(cell2->payload_len, >, 1);

  tt_int_op(cell1->payload_len, ==,
            certs_cell_parse(&cc1, cell1->payload, cell1->payload_len));
  tt_int_op(cell2->payload_len, ==,
            certs_cell_parse(&cc2, cell2->payload, cell2->payload_len));

  tt_int_op(2, ==, cc1->n_certs);
  tt_int_op(2, ==, cc2->n_certs);

  tt_int_op(certs_cell_get_certs(cc1, 0)->cert_type, ==,
            CERTTYPE_RSA1024_ID_AUTH);
  tt_int_op(certs_cell_get_certs(cc1, 1)->cert_type, ==,
            CERTTYPE_RSA1024_ID_ID);

  tt_int_op(certs_cell_get_certs(cc2, 0)->cert_type, ==,
            CERTTYPE_RSA1024_ID_LINK);
  tt_int_op(certs_cell_get_certs(cc2, 1)->cert_type, ==,
            CERTTYPE_RSA1024_ID_ID);

  chan1 = tor_malloc_zero(sizeof(*chan1));
  channel_tls_common_init(chan1);
  c1->chan = chan1;
  chan1->conn = c1;
  c1->base_.address = tor_strdup("C1");
  c1->tls = tor_tls_new(-1, 0);
  c1->link_proto = 4;
  c1->base_.conn_array_index = -1;
  crypto_pk_get_digest(key2, c1->identity_digest);

  channel_tls_process_certs_cell(cell2, chan1);

  tt_assert(c1->handshake_state->received_certs_cell);
  tt_assert(c1->handshake_state->auth_cert == NULL);
  tt_assert(c1->handshake_state->id_cert);
  tt_assert(! tor_mem_is_zero(
                  (char*)c1->handshake_state->authenticated_peer_id, 20));

  chan2 = tor_malloc_zero(sizeof(*chan2));
  channel_tls_common_init(chan2);
  c2->chan = chan2;
  chan2->conn = c2;
  c2->base_.address = tor_strdup("C2");
  c2->tls = tor_tls_new(-1, 1);
  c2->link_proto = 4;
  c2->base_.conn_array_index = -1;
  crypto_pk_get_digest(key1, c2->identity_digest);

  channel_tls_process_certs_cell(cell1, chan2);

  tt_assert(c2->handshake_state->received_certs_cell);
  tt_assert(c2->handshake_state->auth_cert);
  tt_assert(c2->handshake_state->id_cert);
  tt_assert(tor_mem_is_zero(
                (char*)c2->handshake_state->authenticated_peer_id, 20));

 done:
  UNMOCK(tor_tls_cert_matches_key);
  UNMOCK(connection_or_write_var_cell_to_buf);
  UNMOCK(connection_or_send_netinfo);
  connection_free_(TO_CONN(c1));
  connection_free_(TO_CONN(c2));
  tor_free(cell1);
  tor_free(cell2);
  certs_cell_free(cc1);
  certs_cell_free(cc2);
  tor_free(chan1);
  tor_free(chan2);
}

typedef struct certs_data_s {
  or_connection_t *c;
  channel_tls_t *chan;
  certs_cell_t *ccell;
  var_cell_t *cell;
} certs_data_t;


static int
recv_certs_cleanup(const struct testcase_t *test, void *obj)
{
  (void)test;
  certs_data_t *d = obj;
  UNMOCK(tor_tls_cert_matches_key);
  UNMOCK(connection_or_send_netinfo);
  UNMOCK(connection_or_close_for_error);

  if (d) {
    tor_free(d->cell);
    certs_cell_free(d->ccell);
    connection_free_(TO_CONN(d->c));
    tor_free(d->chan);
    tor_free(d);
  }
  return 1;
}

static void *
recv_certs_setup(const struct testcase_t *test)
{
  (void)test;
  certs_data_t *d = tor_malloc_zero(sizeof(*d));
  certs_cell_cert_t *ccc1 = NULL;
  certs_cell_cert_t *ccc2 = NULL;
  ssize_t n;

  d->c = or_connection_new(CONN_TYPE_OR, AF_INET);
  d->chan = tor_malloc_zero(sizeof(*d->chan));
  d->c->chan = d->chan;
  d->c->base_.address = tor_strdup("HaveAnAddress");
  d->c->base_.state = OR_CONN_STATE_OR_HANDSHAKING_V3;
  d->chan->conn = d->c;
  tt_int_op(connection_init_or_handshake_state(d->c, 1), ==, 0);
  d->c->link_proto = 4;

  crypto_pk_t *key1 = NULL, *key2 = NULL;
  key1 = pk_generate(2);
  key2 = pk_generate(3);

  tt_int_op(tor_tls_context_init(TOR_TLS_CTX_IS_PUBLIC_SERVER,
                                 key1, key2, 86400), ==, 0);
  d->ccell = certs_cell_new();
  ccc1 = certs_cell_cert_new();
  certs_cell_add_certs(d->ccell, ccc1);
  ccc2 = certs_cell_cert_new();
  certs_cell_add_certs(d->ccell, ccc2);
  d->ccell->n_certs = 2;
  ccc1->cert_type = 1;
  ccc2->cert_type = 2;

  const tor_x509_cert_t *a,*b;
  const uint8_t *enca, *encb;
  size_t lena, lenb;
  tor_tls_get_my_certs(1, &a, &b);
  tor_x509_cert_get_der(a, &enca, &lena);
  tor_x509_cert_get_der(b, &encb, &lenb);
  certs_cell_cert_setlen_body(ccc1, lena);
  ccc1->cert_len = lena;
  certs_cell_cert_setlen_body(ccc2, lenb);
  ccc2->cert_len = lenb;

  memcpy(certs_cell_cert_getarray_body(ccc1), enca, lena);
  memcpy(certs_cell_cert_getarray_body(ccc2), encb, lenb);

  d->cell = var_cell_new(4096);
  d->cell->command = CELL_CERTS;

  n = certs_cell_encode(d->cell->payload, 4096, d->ccell);
  tt_int_op(n, >, 0);
  d->cell->payload_len = n;

  MOCK(tor_tls_cert_matches_key, mock_tls_cert_matches_key);
  MOCK(connection_or_send_netinfo, mock_send_netinfo);
  MOCK(connection_or_close_for_error, mock_close_for_err);

  tt_int_op(0, ==, d->c->handshake_state->received_certs_cell);
  tt_int_op(0, ==, mock_send_authenticate_called);
  tt_int_op(0, ==, mock_send_netinfo_called);

  return d;
 done:
  recv_certs_cleanup(test, d);
  return NULL;
}

static struct testcase_setup_t setup_recv_certs = {
  .setup_fn = recv_certs_setup,
  .cleanup_fn = recv_certs_cleanup
};

static void
test_link_handshake_recv_certs_ok(void *arg)
{
  certs_data_t *d = arg;
  channel_tls_process_certs_cell(d->cell, d->chan);
  tt_int_op(0, ==, mock_close_called);
  tt_int_op(d->c->handshake_state->authenticated, ==, 1);
  tt_int_op(d->c->handshake_state->received_certs_cell, ==, 1);
  tt_assert(d->c->handshake_state->id_cert != NULL);
  tt_assert(d->c->handshake_state->auth_cert == NULL);

 done:
  ;
}

static void
test_link_handshake_recv_certs_ok_server(void *arg)
{
  certs_data_t *d = arg;
  d->c->handshake_state->started_here = 0;
  certs_cell_get_certs(d->ccell, 0)->cert_type = 3;
  certs_cell_get_certs(d->ccell, 1)->cert_type = 2;
  ssize_t n = certs_cell_encode(d->cell->payload, 2048, d->ccell);
  tt_int_op(n, >, 0);
  d->cell->payload_len = n;
  channel_tls_process_certs_cell(d->cell, d->chan);
  tt_int_op(0, ==, mock_close_called);
  tt_int_op(d->c->handshake_state->authenticated, ==, 0);
  tt_int_op(d->c->handshake_state->received_certs_cell, ==, 1);
  tt_assert(d->c->handshake_state->id_cert != NULL);
  tt_assert(d->c->handshake_state->auth_cert != NULL);

 done:
  ;
}

#define CERTS_FAIL(name, code)                          \
  static void                                                           \
  test_link_handshake_recv_certs_ ## name (void *arg)                   \
  {                                                                     \
    certs_data_t *d = arg;                                              \
    { code ; }                                                          \
    channel_tls_process_certs_cell(d->cell, d->chan);                   \
    tt_int_op(1, ==, mock_close_called);                                \
    tt_int_op(0, ==, mock_send_authenticate_called);                    \
    tt_int_op(0, ==, mock_send_netinfo_called);                         \
  done:                                                                 \
    ;                                                                   \
  }

CERTS_FAIL(badstate, d->c->base_.state = OR_CONN_STATE_CONNECTING)
CERTS_FAIL(badproto, d->c->link_proto = 2)
CERTS_FAIL(duplicate, d->c->handshake_state->received_certs_cell = 1)
CERTS_FAIL(already_authenticated,
           d->c->handshake_state->authenticated = 1)
CERTS_FAIL(empty, d->cell->payload_len = 0)
CERTS_FAIL(bad_circid, d->cell->circ_id = 1)
CERTS_FAIL(truncated_1, d->cell->payload[0] = 5)
CERTS_FAIL(truncated_2, {
           d->cell->payload_len = 4;
           memcpy(d->cell->payload, "\x01\x01\x00\x05", 4);})
CERTS_FAIL(truncated_3, {
           d->cell->payload_len = 7;
           memcpy(d->cell->payload, "\x01\x01\x00\x05""abc", 7);})
#define REENCODE() do {                                                 \
    ssize_t n = certs_cell_encode(d->cell->payload, 4096, d->ccell);    \
    tt_int_op(n, >, 0);                                                 \
    d->cell->payload_len = n;                                           \
  } while (0)

CERTS_FAIL(not_x509, {
    certs_cell_cert_setlen_body(certs_cell_get_certs(d->ccell, 0), 3);
    certs_cell_get_certs(d->ccell, 0)->cert_len = 3;
    REENCODE();
    })
CERTS_FAIL(both_link, {
    certs_cell_get_certs(d->ccell, 0)->cert_type = 1;
    certs_cell_get_certs(d->ccell, 1)->cert_type = 1;
    REENCODE();
    })
CERTS_FAIL(both_id_rsa, {
    certs_cell_get_certs(d->ccell, 0)->cert_type = 2;
    certs_cell_get_certs(d->ccell, 1)->cert_type = 2;
    REENCODE();
    })
CERTS_FAIL(both_auth, {
    certs_cell_get_certs(d->ccell, 0)->cert_type = 3;
    certs_cell_get_certs(d->ccell, 1)->cert_type = 3;
    REENCODE();
    })
CERTS_FAIL(wrong_labels_1, {
    certs_cell_get_certs(d->ccell, 0)->cert_type = 2;
    certs_cell_get_certs(d->ccell, 1)->cert_type = 1;
    REENCODE();
    })
CERTS_FAIL(wrong_labels_2, {
    const tor_x509_cert_t *a;
    const tor_x509_cert_t *b;
    const uint8_t *enca;
    size_t lena;
    tor_tls_get_my_certs(1, &a, &b);
    tor_x509_cert_get_der(a, &enca, &lena);
    certs_cell_cert_setlen_body(certs_cell_get_certs(d->ccell, 1), lena);
    memcpy(certs_cell_cert_getarray_body(certs_cell_get_certs(d->ccell, 1)),
           enca, lena);
    certs_cell_get_certs(d->ccell, 1)->cert_len = lena;
    REENCODE();
  })
CERTS_FAIL(wrong_labels_3, {
    certs_cell_get_certs(d->ccell, 0)->cert_type = 2;
    certs_cell_get_certs(d->ccell, 1)->cert_type = 3;
    REENCODE();
    })
CERTS_FAIL(server_missing_certs, {
  d->c->handshake_state->started_here = 0;
  })
CERTS_FAIL(server_wrong_labels_1, {
  d->c->handshake_state->started_here = 0;
  certs_cell_get_certs(d->ccell, 0)->cert_type = 2;
  certs_cell_get_certs(d->ccell, 1)->cert_type = 3;
  REENCODE();
  })

static void
test_link_handshake_send_authchallenge(void *arg)
{
  (void)arg;

  or_connection_t *c1 = or_connection_new(CONN_TYPE_OR, AF_INET);
  var_cell_t *cell1=NULL, *cell2=NULL;

  MOCK(connection_or_write_var_cell_to_buf, mock_write_var_cell);

  tt_int_op(connection_init_or_handshake_state(c1, 0), ==, 0);
  c1->base_.state = OR_CONN_STATE_OR_HANDSHAKING_V3;
  tt_assert(! mock_got_var_cell);
  tt_int_op(0, ==, connection_or_send_auth_challenge_cell(c1));
  cell1 = mock_got_var_cell;
  tt_int_op(0, ==, connection_or_send_auth_challenge_cell(c1));
  cell2 = mock_got_var_cell;
  tt_int_op(36, ==, cell1->payload_len);
  tt_int_op(36, ==, cell2->payload_len);
  tt_int_op(0, ==, cell1->circ_id);
  tt_int_op(0, ==, cell2->circ_id);
  tt_int_op(CELL_AUTH_CHALLENGE, ==, cell1->command);
  tt_int_op(CELL_AUTH_CHALLENGE, ==, cell2->command);

  tt_mem_op("\x00\x01\x00\x01", ==, cell1->payload + 32, 4);
  tt_mem_op("\x00\x01\x00\x01", ==, cell2->payload + 32, 4);
  tt_mem_op(cell1->payload, !=, cell2->payload, 32);

 done:
  UNMOCK(connection_or_write_var_cell_to_buf);
  connection_free_(TO_CONN(c1));
  tor_free(cell1);
  tor_free(cell2);
}

typedef struct authchallenge_data_s {
  or_connection_t *c;
  channel_tls_t *chan;
  var_cell_t *cell;
} authchallenge_data_t;

static int
recv_authchallenge_cleanup(const struct testcase_t *test, void *obj)
{
  (void)test;
  authchallenge_data_t *d = obj;

  UNMOCK(connection_or_send_netinfo);
  UNMOCK(connection_or_close_for_error);
  UNMOCK(connection_or_send_authenticate_cell);

  if (d) {
    tor_free(d->cell);
    connection_free_(TO_CONN(d->c));
    tor_free(d->chan);
    tor_free(d);
  }
  return 1;
}

static void *
recv_authchallenge_setup(const struct testcase_t *test)
{
  (void)test;
  authchallenge_data_t *d = tor_malloc_zero(sizeof(*d));
  d->c = or_connection_new(CONN_TYPE_OR, AF_INET);
  d->chan = tor_malloc_zero(sizeof(*d->chan));
  d->c->chan = d->chan;
  d->c->base_.address = tor_strdup("HaveAnAddress");
  d->c->base_.state = OR_CONN_STATE_OR_HANDSHAKING_V3;
  d->chan->conn = d->c;
  tt_int_op(connection_init_or_handshake_state(d->c, 1), ==, 0);
  d->c->link_proto = 4;
  d->c->handshake_state->received_certs_cell = 1;
  d->cell = var_cell_new(128);
  d->cell->payload_len = 38;
  d->cell->payload[33] = 2;
  d->cell->payload[35] = 7;
  d->cell->payload[37] = 1;
  d->cell->command = CELL_AUTH_CHALLENGE;

  get_options_mutable()->ORPort_set = 1;

  MOCK(connection_or_close_for_error, mock_close_for_err);
  MOCK(connection_or_send_netinfo, mock_send_netinfo);
  MOCK(connection_or_send_authenticate_cell, mock_send_authenticate);

  tt_int_op(0, ==, d->c->handshake_state->received_auth_challenge);
  tt_int_op(0, ==, mock_send_authenticate_called);
  tt_int_op(0, ==, mock_send_netinfo_called);

  return d;
 done:
  recv_authchallenge_cleanup(test, d);
  return NULL;
}

static struct testcase_setup_t setup_recv_authchallenge = {
  .setup_fn = recv_authchallenge_setup,
  .cleanup_fn = recv_authchallenge_cleanup
};

static void
test_link_handshake_recv_authchallenge_ok(void *arg)
{
  authchallenge_data_t *d = arg;

  channel_tls_process_auth_challenge_cell(d->cell, d->chan);
  tt_int_op(0, ==, mock_close_called);
  tt_int_op(1, ==, d->c->handshake_state->received_auth_challenge);
  tt_int_op(1, ==, mock_send_authenticate_called);
  tt_int_op(1, ==, mock_send_netinfo_called);
 done:
  ;
}

static void
test_link_handshake_recv_authchallenge_ok_noserver(void *arg)
{
  authchallenge_data_t *d = arg;
  get_options_mutable()->ORPort_set = 0;

  channel_tls_process_auth_challenge_cell(d->cell, d->chan);
  tt_int_op(0, ==, mock_close_called);
  tt_int_op(1, ==, d->c->handshake_state->received_auth_challenge);
  tt_int_op(0, ==, mock_send_authenticate_called);
  tt_int_op(0, ==, mock_send_netinfo_called);
 done:
  ;
}

static void
test_link_handshake_recv_authchallenge_ok_unrecognized(void *arg)
{
  authchallenge_data_t *d = arg;
  d->cell->payload[37] = 99;

  channel_tls_process_auth_challenge_cell(d->cell, d->chan);
  tt_int_op(0, ==, mock_close_called);
  tt_int_op(1, ==, d->c->handshake_state->received_auth_challenge);
  tt_int_op(0, ==, mock_send_authenticate_called);
  tt_int_op(1, ==, mock_send_netinfo_called);
 done:
  ;
}

#define AUTHCHALLENGE_FAIL(name, code)                          \
  static void                                                           \
  test_link_handshake_recv_authchallenge_ ## name (void *arg)           \
  {                                                                     \
    authchallenge_data_t *d = arg;                                      \
    { code ; }                                                          \
    channel_tls_process_auth_challenge_cell(d->cell, d->chan);          \
    tt_int_op(1, ==, mock_close_called);                                \
    tt_int_op(0, ==, mock_send_authenticate_called);                    \
    tt_int_op(0, ==, mock_send_netinfo_called);                         \
  done:                                                                 \
    ;                                                                   \
  }

AUTHCHALLENGE_FAIL(badstate,
                   d->c->base_.state = OR_CONN_STATE_CONNECTING)
AUTHCHALLENGE_FAIL(badproto,
                   d->c->link_proto = 2)
AUTHCHALLENGE_FAIL(as_server,
                   d->c->handshake_state->started_here = 0;)
AUTHCHALLENGE_FAIL(duplicate,
                   d->c->handshake_state->received_auth_challenge = 1)
AUTHCHALLENGE_FAIL(nocerts,
                   d->c->handshake_state->received_certs_cell = 0)
AUTHCHALLENGE_FAIL(tooshort,
                   d->cell->payload_len = 33)
AUTHCHALLENGE_FAIL(truncated,
                   d->cell->payload_len = 34)
AUTHCHALLENGE_FAIL(nonzero_circid,
                   d->cell->circ_id = 1337)

#define TEST(name, flags)                                       \
  { #name , test_link_handshake_ ## name, (flags), NULL, NULL }

#define TEST_RCV_AUTHCHALLENGE(name)                            \
  { "recv_authchallenge/" #name ,                               \
    test_link_handshake_recv_authchallenge_ ## name, TT_FORK,   \
      &setup_recv_authchallenge, NULL }

#define TEST_RCV_CERTS(name)                                    \
  { "recv_certs/" #name ,                                       \
      test_link_handshake_recv_certs_ ## name, TT_FORK,         \
      &setup_recv_certs, NULL }

struct testcase_t link_handshake_tests[] = {
  TEST(certs_ok, TT_FORK),
  //TEST(certs_bad, TT_FORK),
  TEST_RCV_CERTS(ok),
  TEST_RCV_CERTS(ok_server),
  TEST_RCV_CERTS(badstate),
  TEST_RCV_CERTS(badproto),
  TEST_RCV_CERTS(duplicate),
  TEST_RCV_CERTS(already_authenticated),
  TEST_RCV_CERTS(empty),
  TEST_RCV_CERTS(bad_circid),
  TEST_RCV_CERTS(truncated_1),
  TEST_RCV_CERTS(truncated_2),
  TEST_RCV_CERTS(truncated_3),
  TEST_RCV_CERTS(not_x509),
  TEST_RCV_CERTS(both_link),
  TEST_RCV_CERTS(both_id_rsa),
  TEST_RCV_CERTS(both_auth),
  TEST_RCV_CERTS(wrong_labels_1),
  TEST_RCV_CERTS(wrong_labels_2),
  TEST_RCV_CERTS(wrong_labels_3),
  TEST_RCV_CERTS(server_missing_certs),
  TEST_RCV_CERTS(server_wrong_labels_1),

  TEST(send_authchallenge, TT_FORK),
  TEST_RCV_AUTHCHALLENGE(ok),
  TEST_RCV_AUTHCHALLENGE(ok_noserver),
  TEST_RCV_AUTHCHALLENGE(ok_unrecognized),
  TEST_RCV_AUTHCHALLENGE(badstate),
  TEST_RCV_AUTHCHALLENGE(badproto),
  TEST_RCV_AUTHCHALLENGE(as_server),
  TEST_RCV_AUTHCHALLENGE(duplicate),
  TEST_RCV_AUTHCHALLENGE(nocerts),
  TEST_RCV_AUTHCHALLENGE(tooshort),
  TEST_RCV_AUTHCHALLENGE(truncated),
  TEST_RCV_AUTHCHALLENGE(nonzero_circid),

  END_OF_TESTCASES
};

