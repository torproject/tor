/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CIRCUITLIST_PRIVATE
#define RELAY_PRIVATE
#include "or.h"
#include "circuitlist.h"
#include "relay.h"
#include "test.h"

static void
test_cq_manip(void *arg)
{
  packed_cell_t *pc1=NULL, *pc2=NULL, *pc3=NULL, *pc4=NULL, *pc_tmp=NULL;
  cell_queue_t cq;
  cell_t cell;
  (void) arg;

  init_cell_pool();
  cell_queue_init(&cq);
  tt_int_op(cq.n, ==, 0);

  pc1 = packed_cell_new();
  pc2 = packed_cell_new();
  pc3 = packed_cell_new();
  pc4 = packed_cell_new();
  tt_assert(pc1 && pc2 && pc3 && pc4);

  tt_ptr_op(NULL, ==, cell_queue_pop(&cq));

  /* Add and remove a singleton. */
  cell_queue_append(&cq, pc1);
  tt_int_op(cq.n, ==, 1);
  tt_ptr_op(pc1, ==, cell_queue_pop(&cq));
  tt_int_op(cq.n, ==, 0);

  /* Add and remove four items */
  cell_queue_append(&cq, pc4);
  cell_queue_append(&cq, pc3);
  cell_queue_append(&cq, pc2);
  cell_queue_append(&cq, pc1);
  tt_int_op(cq.n, ==, 4);
  tt_ptr_op(pc4, ==, cell_queue_pop(&cq));
  tt_ptr_op(pc3, ==, cell_queue_pop(&cq));
  tt_ptr_op(pc2, ==, cell_queue_pop(&cq));
  tt_ptr_op(pc1, ==, cell_queue_pop(&cq));
  tt_int_op(cq.n, ==, 0);
  tt_ptr_op(NULL, ==, cell_queue_pop(&cq));

  /* Try a packed copy (wide, then narrow, which is a bit of a cheat, since a
   * real cell queue has only one type.) */
  memset(&cell, 0, sizeof(cell));
  cell.circ_id = 0x12345678;
  cell.command = 10;
  strlcpy((char*)cell.payload, "Lorax ipsum gruvvulus thneed amet, snergelly "
          "once-ler lerkim, sed do barbaloot tempor gluppitus ut labore et "
          "truffula magna aliqua.",
          sizeof(cell.payload));
  cell_queue_append_packed_copy(&cq, &cell, 1 /*wide*/, 0 /*stats*/);
  cell.circ_id = 0x2013;
  cell_queue_append_packed_copy(&cq, &cell, 0 /*wide*/, 0 /*stats*/);
  tt_int_op(cq.n, ==, 2);

  pc_tmp = cell_queue_pop(&cq);
  tt_int_op(cq.n, ==, 1);
  tt_ptr_op(pc_tmp, !=, NULL);
  test_mem_op(pc_tmp->body, ==, "\x12\x34\x56\x78\x0a", 5);
  test_mem_op(pc_tmp->body+5, ==, cell.payload, sizeof(cell.payload));
  packed_cell_free(pc_tmp);

  pc_tmp = cell_queue_pop(&cq);
  tt_int_op(cq.n, ==, 0);
  tt_ptr_op(pc_tmp, !=, NULL);
  test_mem_op(pc_tmp->body, ==, "\x20\x13\x0a", 3);
  test_mem_op(pc_tmp->body+3, ==, cell.payload, sizeof(cell.payload));
  packed_cell_free(pc_tmp);
  pc_tmp = NULL;

  tt_ptr_op(NULL, ==, cell_queue_pop(&cq));

  /* Now make sure cell_queue_clear works. */
  cell_queue_append(&cq, pc2);
  cell_queue_append(&cq, pc1);
  tt_int_op(cq.n, ==, 2);
  cell_queue_clear(&cq);
  pc2 = pc1 = NULL; /* prevent double-free */
  tt_int_op(cq.n, ==, 0);

 done:
  packed_cell_free(pc1);
  packed_cell_free(pc2);
  packed_cell_free(pc3);
  packed_cell_free(pc4);
  packed_cell_free(pc_tmp);

  cell_queue_clear(&cq);
  free_cell_pool();
}

struct testcase_t cell_queue_tests[] = {
  { "basic", test_cq_manip, TT_FORK, NULL, NULL, },
  END_OF_TESTCASES
};
