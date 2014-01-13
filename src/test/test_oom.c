/* Copyright (c) 2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* Unit tests for OOM handling logic */

#define RELAY_PRIVATE
#define BUFFERS_PRIVATE
#define CIRCUITLIST_PRIVATE
#include "or.h"
#include "buffers.h"
#include "circuitlist.h"
#include "compat_libevent.h"
#include "connection.h"
#include "config.h"
#include "mempool.h"
#include "relay.h"
#include "test.h"

/* small replacement mock for circuit_mark_for_close_ to avoid doing all
 * the other bookkeeping that comes with marking circuits. */
static void
circuit_mark_for_close_dummy_(circuit_t *circ, int reason, int line,
                              const char *file)
{
  (void) reason;
  if (circ->marked_for_close) {
    TT_FAIL(("Circuit already marked for close at %s:%d, but we are marking "
             "it again at %s:%d",
             circ->marked_for_close_file, (int)circ->marked_for_close,
             file, line));
  }

  circ->marked_for_close = line;
  circ->marked_for_close_file = file;
}

static circuit_t *
dummy_or_circuit_new(int n_p_cells, int n_n_cells)
{
  or_circuit_t *circ = or_circuit_new(0, NULL);
  int i;
  cell_t cell;

  for (i=0; i < n_p_cells; ++i) {
    crypto_rand((void*)&cell, sizeof(cell));
    cell_queue_append_packed_copy(TO_CIRCUIT(circ), &circ->p_chan_cells,
                                  0, &cell, 1, 0);
  }

  for (i=0; i < n_n_cells; ++i) {
    crypto_rand((void*)&cell, sizeof(cell));
    cell_queue_append_packed_copy(TO_CIRCUIT(circ),
                                  &TO_CIRCUIT(circ)->n_chan_cells,
                                  1, &cell, 1, 0);
  }

  TO_CIRCUIT(circ)->purpose = CIRCUIT_PURPOSE_OR;
  return TO_CIRCUIT(circ);
}

static circuit_t *
dummy_origin_circuit_new(int n_cells)
{
  origin_circuit_t *circ = origin_circuit_new();
  int i;
  cell_t cell;

  for (i=0; i < n_cells; ++i) {
    crypto_rand((void*)&cell, sizeof(cell));
    cell_queue_append_packed_copy(TO_CIRCUIT(circ),
                                  &TO_CIRCUIT(circ)->n_chan_cells,
                                  1, &cell, 1, 0);
  }

  TO_CIRCUIT(circ)->purpose = CIRCUIT_PURPOSE_C_GENERAL;
  return TO_CIRCUIT(circ);
}

#if 0
static void
add_bytes_to_buf(generic_buffer_t *buf, size_t n_bytes)
{
  char b[3000];

  while (n_bytes) {
    size_t this_add = n_bytes > sizeof(buf) ? sizeof(buf) : n_bytes;
    crypto_rand(b, sizeof(b));
    generic_buffer_add(buf, b, this_add);
    n_bytes -= this_add;
  }
}

static edge_connection_t *
dummy_edge_conn_new(int type, size_t in_bytes, size_t out_bytes)
{
  edge_connection_t *conn = edge_connection_new(type, AF_INET);

  /* We add these bytes directly to the buffers, to avoid all the
   * edge connection read/write machinery. */
  add_bytes_to_buf(TO_CONN(conn)->inbuf, in_bytes);
  add_bytes_to_buf(TO_CONN(conn)->outbuf, out_bytes);

  return conn;
}
#endif

/** Run unit tests for buffers.c */
static void
test_oom_circbuf(void *arg)
{
  or_options_t *options = get_options_mutable();
  circuit_t *c1 = NULL, *c2 = NULL, *c3 = NULL, *c4 = NULL;
  struct timeval tv = { 1389631048, 0 };

  (void) arg;

  MOCK(circuit_mark_for_close_, circuit_mark_for_close_dummy_);
  init_cell_pool();

  /* Far too low for real life. */
  options->MaxMemInQueues = 256*packed_cell_mem_cost();
  options->CellStatistics = 0;

  tt_int_op(cell_queues_check_size(), ==, 0); /* We don't start out OOM. */
  tt_int_op(cell_queues_get_total_allocation(), ==, 0);
  tt_int_op(buf_get_total_allocation(), ==, 0);

  /* Now we're going to fake up some circuits and get them added to the global
     circuit list. */
  tv.tv_usec = 0;
  tor_gettimeofday_cache_set(&tv);
  c1 = dummy_origin_circuit_new(30);
  tv.tv_usec = 10*1000;
  tor_gettimeofday_cache_set(&tv);
  c2 = dummy_or_circuit_new(20, 20);

  tt_int_op(packed_cell_mem_cost(), ==,
            sizeof(packed_cell_t) + MP_POOL_ITEM_OVERHEAD);
  tt_int_op(cell_queues_get_total_allocation(), ==,
            packed_cell_mem_cost() * 70);
  tt_int_op(cell_queues_check_size(), ==, 0); /* We are still not OOM */

  tv.tv_usec = 20*1000;
  tor_gettimeofday_cache_set(&tv);
  c3 = dummy_or_circuit_new(100, 85);
  tt_int_op(cell_queues_check_size(), ==, 0); /* We are still not OOM */
  tt_int_op(cell_queues_get_total_allocation(), ==,
            packed_cell_mem_cost() * 255);

  tv.tv_usec = 30*1000;
  tor_gettimeofday_cache_set(&tv);
  /* Adding this cell will trigger our OOM handler. */
  c4 = dummy_or_circuit_new(2, 0);

  tt_int_op(cell_queues_get_total_allocation(), ==,
            packed_cell_mem_cost() * 257);

  tt_int_op(cell_queues_check_size(), ==, 1); /* We are now OOM */

  tt_assert(c1->marked_for_close);
  tt_assert(! c2->marked_for_close);
  tt_assert(! c3->marked_for_close);
  tt_assert(! c4->marked_for_close);

  tt_int_op(cell_queues_get_total_allocation(), ==,
            packed_cell_mem_cost() * (257 - 30));

  circuit_free(c1);
  tv.tv_usec = 0;
  tor_gettimeofday_cache_set(&tv); /* go back in time */
  c1 = dummy_or_circuit_new(90, 0);

  tv.tv_usec = 40*1000; /* go back to the future */
  tor_gettimeofday_cache_set(&tv);

  tt_int_op(cell_queues_check_size(), ==, 1); /* We are now OOM */

  tt_assert(c1->marked_for_close);
  tt_assert(! c2->marked_for_close);
  tt_assert(! c3->marked_for_close);
  tt_assert(! c4->marked_for_close);

  tt_int_op(cell_queues_get_total_allocation(), ==,
            packed_cell_mem_cost() * (257 - 30));

 done:
  circuit_free(c1);
  circuit_free(c2);
  circuit_free(c3);
  circuit_free(c4);

  UNMOCK(circuit_mark_for_close_);
}

struct testcase_t oom_tests[] = {
  { "circbuf", test_oom_circbuf, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

