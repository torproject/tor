/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONNECTION_PRIVATE
#define EXT_ORPORT_PRIVATE
#include "or.h"
#include "buffers.h"
#include "connection.h"
#include "ext_orport.h"
#include "test.h"

/* Test connection_or_remove_from_ext_or_id_map and
 * connection_or_set_ext_or_identifier */
static void
test_ext_or_id_map(void *arg)
{
  or_connection_t *c1 = NULL, *c2 = NULL, *c3 = NULL;
  char *idp = NULL, *idp2 = NULL;
  (void)arg;

  /* pre-initialization */
  tt_ptr_op(NULL, ==, connection_or_get_by_ext_or_id("xxxxxxxxxxxxxxxxxxxx"));

  c1 = or_connection_new(CONN_TYPE_EXT_OR, AF_INET);
  c2 = or_connection_new(CONN_TYPE_EXT_OR, AF_INET);
  c3 = or_connection_new(CONN_TYPE_OR, AF_INET);

  tt_ptr_op(c1->ext_or_conn_id, !=, NULL);
  tt_ptr_op(c2->ext_or_conn_id, !=, NULL);
  tt_ptr_op(c3->ext_or_conn_id, ==, NULL);

  tt_ptr_op(c1, ==, connection_or_get_by_ext_or_id(c1->ext_or_conn_id));
  tt_ptr_op(c2, ==, connection_or_get_by_ext_or_id(c2->ext_or_conn_id));
  tt_ptr_op(NULL, ==, connection_or_get_by_ext_or_id("xxxxxxxxxxxxxxxxxxxx"));

  idp = tor_memdup(c2->ext_or_conn_id, EXT_OR_CONN_ID_LEN);

  /* Give c2 a new ID. */
  connection_or_set_ext_or_identifier(c2);
  test_mem_op(idp, !=, c2->ext_or_conn_id, EXT_OR_CONN_ID_LEN);
  idp2 = tor_memdup(c2->ext_or_conn_id, EXT_OR_CONN_ID_LEN);
  tt_assert(!tor_digest_is_zero(idp2));

  tt_ptr_op(NULL, ==, connection_or_get_by_ext_or_id(idp));
  tt_ptr_op(c2, ==, connection_or_get_by_ext_or_id(idp2));

  /* Now remove it. */
  connection_or_remove_from_ext_or_id_map(c2);
  tt_ptr_op(NULL, ==, connection_or_get_by_ext_or_id(idp));
  tt_ptr_op(NULL, ==, connection_or_get_by_ext_or_id(idp2));

 done:
  if (c1)
    connection_free_(TO_CONN(c1));
  if (c2)
    connection_free_(TO_CONN(c2));
  if (c3)
    connection_free_(TO_CONN(c3));
  tor_free(idp);
  tor_free(idp2);
  connection_or_clear_ext_or_id_map();
}

/* Simple connection_write_to_buf_impl_ replacement that unconditionally
 * writes to outbuf. */
static void
connection_write_to_buf_impl_replacement(const char *string, size_t len,
                                         connection_t *conn, int zlib)
{
  (void) zlib;

  tor_assert(string);
  tor_assert(conn);
  write_to_buf(string, len, conn->outbuf);
}

static char *
buf_get_contents(buf_t *buf, size_t *sz_out)
{
  char *out;
  *sz_out = buf_datalen(buf);
  if (*sz_out >= ULONG_MAX)
    return NULL; /* C'mon, really? */
  out = tor_malloc(*sz_out + 1);
  if (fetch_from_buf(out, (unsigned long)*sz_out, buf) != 0) {
    tor_free(out);
    return NULL;
  }
  out[*sz_out] = '\0'; /* Hopefully gratuitous. */
  return out;
}

static void
test_ext_or_write_command(void *arg)
{
  or_connection_t *c1;
  char *cp = NULL;
  char *buf = NULL;
  size_t sz;

  (void) arg;
  MOCK(connection_write_to_buf_impl_,
       connection_write_to_buf_impl_replacement);

  c1 = or_connection_new(CONN_TYPE_EXT_OR, AF_INET);
  tt_assert(c1);

  /* Length too long */
  tt_int_op(connection_write_ext_or_command(TO_CONN(c1), 100, "X", 100000),
            <, 0);

  /* Empty command */
  tt_int_op(connection_write_ext_or_command(TO_CONN(c1), 0x99, NULL, 0),
            ==, 0);
  cp = buf_get_contents(TO_CONN(c1)->outbuf, &sz);
  tt_int_op(sz, ==, 4);
  test_mem_op(cp, ==, "\x00\x99\x00\x00", 4);
  tor_free(cp);

  /* Medium command. */
  tt_int_op(connection_write_ext_or_command(TO_CONN(c1), 0x99,
                                            "Wai\0Hello", 9), ==, 0);
  cp = buf_get_contents(TO_CONN(c1)->outbuf, &sz);
  tt_int_op(sz, ==, 13);
  test_mem_op(cp, ==, "\x00\x99\x00\x09Wai\x00Hello", 13);
  tor_free(cp);

  /* Long command */
  buf = tor_malloc(65535);
  memset(buf, 'x', 65535);
  tt_int_op(connection_write_ext_or_command(TO_CONN(c1), 0xf00d,
                                            buf, 65535), ==, 0);
  cp = buf_get_contents(TO_CONN(c1)->outbuf, &sz);
  tt_int_op(sz, ==, 65539);
  test_mem_op(cp, ==, "\xf0\x0d\xff\xff", 4);
  test_mem_op(cp+4, ==, buf, 65535);
  tor_free(cp);

 done:
  if (c1)
    connection_free_(TO_CONN(c1));
  tor_free(cp);
  tor_free(buf);
  UNMOCK(connection_write_to_buf_impl_);
}

struct testcase_t extorport_tests[] = {
  { "id_map", test_ext_or_id_map, TT_FORK, NULL, NULL },
  { "write_command", test_ext_or_write_command, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

