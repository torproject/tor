/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONNECTION_PRIVATE
#include "or.h"
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

struct testcase_t extorport_tests[] = {
  { "id_map", test_ext_or_id_map, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
