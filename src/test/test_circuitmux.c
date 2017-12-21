/* Copyright (c) 2013-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define TOR_CHANNEL_INTERNAL_
#define CIRCUITMUX_PRIVATE
#define RELAY_PRIVATE
#include "or.h"
#include "channel.h"
#include "circuitmux.h"
#include "relay.h"
#include "scheduler.h"
#include "test.h"

/* XXXX duplicated function from test_circuitlist.c */
static channel_t *
new_fake_channel(void)
{
  channel_t *chan = tor_malloc_zero(sizeof(channel_t));
  channel_init(chan);
  return chan;
}

static int
has_queued_writes(channel_t *c)
{
  (void) c;
  return 1;
}

/** Test destroy cell queue with no interference from other queues. */
static void
test_cmux_destroy_cell_queue(void *arg)
{
  circuitmux_t *cmux = NULL;
  channel_t *ch = NULL;
  circuit_t *circ = NULL;
  destroy_cell_queue_t *cq = NULL;
  packed_cell_t *pc = NULL;
  destroy_cell_t *dc = NULL;

  scheduler_init();

  (void) arg;

  cmux = circuitmux_alloc();
  tt_assert(cmux);
  ch = new_fake_channel();
  ch->has_queued_writes = has_queued_writes;
  ch->wide_circ_ids = 1;

  circ = circuitmux_get_first_active_circuit(cmux, &cq);
  tt_ptr_op(circ, OP_EQ, NULL);
  tt_ptr_op(cq, OP_EQ, NULL);

  circuitmux_append_destroy_cell(ch, cmux, 100, 10);
  circuitmux_append_destroy_cell(ch, cmux, 190, 6);
  circuitmux_append_destroy_cell(ch, cmux, 30, 1);

  tt_int_op(circuitmux_num_cells(cmux), OP_EQ, 3);

  circ = circuitmux_get_first_active_circuit(cmux, &cq);
  tt_ptr_op(circ, OP_EQ, NULL);
  tt_assert(cq);

  tt_int_op(cq->n, OP_EQ, 3);

  dc = destroy_cell_queue_pop(cq);
  tt_assert(dc);
  tt_uint_op(dc->circid, OP_EQ, 100);

  tt_int_op(circuitmux_num_cells(cmux), OP_EQ, 2);

 done:
  circuitmux_free(cmux);
  channel_free(ch);
  packed_cell_free(pc);
  tor_free(dc);
}

struct testcase_t circuitmux_tests[] = {
  { "destroy_cell_queue", test_cmux_destroy_cell_queue, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

