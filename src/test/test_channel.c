/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define TOR_CHANNEL_INTERNAL_
#include "or.h"
#include "channel.h"
/* For channel_note_destroy_not_pending */
#include "circuitlist.h"
/* For var_cell_free */
#include "connection_or.h"
/* For packed_cell stuff */
#define RELAY_PRIVATE
#include "relay.h"
/* For init/free stuff */
#include "scheduler.h"
#include "test.h"

static int test_chan_accept_cells = 0;
static int test_cells_written = 0;
static int test_destroy_not_pending_calls = 0;
static double test_overhead_estimate = 1.0f;

static void channel_note_destroy_not_pending_mock(channel_t *ch,
                                                  circid_t circid);
static void chan_test_close(channel_t *ch);
static size_t chan_test_num_bytes_queued(channel_t *ch);
static int chan_test_num_cells_writeable(channel_t *ch);
static int chan_test_write_cell(channel_t *ch, cell_t *cell);
static int chan_test_write_packed_cell(channel_t *ch,
                                       packed_cell_t *packed_cell);
static int chan_test_write_var_cell(channel_t *ch, var_cell_t *var_cell);
static void make_fake_cell(cell_t *c);
static void make_fake_var_cell(var_cell_t *c);
static channel_t * new_fake_channel(void);
static void scheduler_release_channel_mock(channel_t *ch);

static void test_channel_multi(void *arg);
static void test_channel_queue_size(void *arg);
static void test_channel_write(void *arg);

static void
channel_note_destroy_not_pending_mock(channel_t *ch,
                                      circid_t circid)
{
  (void)ch;
  (void)circid;

  ++test_destroy_not_pending_calls;
}

static void
chan_test_close(channel_t *ch)
{
  test_assert(ch);

 done:
  return;
}

static double
chan_test_get_overhead_estimate(channel_t *ch)
{
  test_assert(ch);

 done:
  return test_overhead_estimate;
}

static size_t
chan_test_num_bytes_queued(channel_t *ch)
{
  test_assert(ch);

 done:
  return 0;
}

static int
chan_test_num_cells_writeable(channel_t *ch)
{
  test_assert(ch);

 done:
  return 32;
}

static int
chan_test_write_cell(channel_t *ch, cell_t *cell)
{
  int rv = 0;

  test_assert(ch);
  test_assert(cell);

  if (test_chan_accept_cells) {
    /* Free the cell and bump the counter */
    tor_free(cell);
    ++test_cells_written;
    rv = 1;
  }
  /* else return 0, we didn't accept it */

 done:
  return rv;
}

static int
chan_test_write_packed_cell(channel_t *ch,
                            packed_cell_t *packed_cell)
{
  int rv = 0;

  test_assert(ch);
  test_assert(packed_cell);

  if (test_chan_accept_cells) {
    /* Free the cell and bump the counter */
    packed_cell_free(packed_cell);
    ++test_cells_written;
    rv = 1;
  }
  /* else return 0, we didn't accept it */

 done:
  return rv;
}

static int
chan_test_write_var_cell(channel_t *ch, var_cell_t *var_cell)
{
  int rv = 0;

  test_assert(ch);
  test_assert(var_cell);

  if (test_chan_accept_cells) {
    /* Free the cell and bump the counter */
    var_cell_free(var_cell);
    ++test_cells_written;
    rv = 1;
  }
  /* else return 0, we didn't accept it */

 done:
  return rv;
}

static void
make_fake_cell(cell_t *c)
{
  test_assert(c != NULL);

  c->circ_id = 1;
  c->command = CELL_RELAY;
  memset(c->payload, 0, CELL_PAYLOAD_SIZE);

 done:
  return;
}

static void
make_fake_var_cell(var_cell_t *c)
{
  test_assert(c != NULL);

  c->circ_id = 1;
  c->command = CELL_VERSIONS;
  c->payload_len = CELL_PAYLOAD_SIZE / 2;
  memset(c->payload, 0, c->payload_len);

 done:
  return;
}

static channel_t *
new_fake_channel(void)
{
  channel_t *chan = tor_malloc_zero(sizeof(channel_t));
  channel_init(chan);

  chan->close = chan_test_close;
  chan->get_overhead_estimate = chan_test_get_overhead_estimate;
  chan->num_bytes_queued = chan_test_num_bytes_queued;
  chan->num_cells_writeable = chan_test_num_cells_writeable;
  chan->write_cell = chan_test_write_cell;
  chan->write_packed_cell = chan_test_write_packed_cell;
  chan->write_var_cell = chan_test_write_var_cell;
  chan->state = CHANNEL_STATE_OPEN;

  return chan;
}

static void
scheduler_release_channel_mock(channel_t *ch)
{
  (void)ch;

  /* Increment counter */
  ++test_releases_count;

  return;
}

static void
test_channel_multi(void *arg)
{
  channel_t *ch1 = NULL, *ch2 = NULL;
  uint64_t global_queue_estimate;
  cell_t *cell = NULL;

  (void)arg;

  /* Accept cells to lower layer */
  test_chan_accept_cells = 1;
  /* Use default overhead factor */
  test_overhead_estimate = 1.0f;

  ch1 = new_fake_channel();
  test_assert(ch1);
  ch2 = new_fake_channel();
  test_assert(ch2);

  /* Initial queue size update */
  channel_update_xmit_queue_size(ch1);
  test_eq(ch1->bytes_queued_for_xmit, 0);
  channel_update_xmit_queue_size(ch2);
  test_eq(ch2->bytes_queued_for_xmit, 0);
  global_queue_estimate = channel_get_global_queue_estimate();
  test_eq(global_queue_estimate, 0);

  /* Queue some cells, check queue estimates */
  cell = tor_malloc_zero(sizeof(cell_t));
  make_fake_cell(cell);
  channel_write_cell(ch1, cell);

  cell = tor_malloc_zero(sizeof(cell_t));
  make_fake_cell(cell);
  channel_write_cell(ch2, cell);

  channel_update_xmit_queue_size(ch1);
  channel_update_xmit_queue_size(ch2);
  test_eq(ch1->bytes_queued_for_xmit, 0);
  test_eq(ch2->bytes_queued_for_xmit, 0);
  global_queue_estimate = channel_get_global_queue_estimate();
  test_eq(global_queue_estimate, 0);

  /* Stop accepting cells at lower layer */
  test_chan_accept_cells = 0;

  /* Queue some cells and check queue estimates */
  cell = tor_malloc_zero(sizeof(cell_t));
  make_fake_cell(cell);
  channel_write_cell(ch1, cell);

  channel_update_xmit_queue_size(ch1);
  test_eq(ch1->bytes_queued_for_xmit, 512);
  global_queue_estimate = channel_get_global_queue_estimate();
  test_eq(global_queue_estimate, 512);

  cell = tor_malloc_zero(sizeof(cell_t));
  make_fake_cell(cell);
  channel_write_cell(ch2, cell);

  channel_update_xmit_queue_size(ch2);
  test_eq(ch2->bytes_queued_for_xmit, 512);
  global_queue_estimate = channel_get_global_queue_estimate();
  test_eq(global_queue_estimate, 1024);

  /* Allow cells through again */
  test_chan_accept_cells = 1;

  /* Flush chan 2 */
  channel_flush_cells(ch2);

  /* Update and check queue sizes */
  channel_update_xmit_queue_size(ch1);
  channel_update_xmit_queue_size(ch2);
  test_eq(ch1->bytes_queued_for_xmit, 512);
  test_eq(ch2->bytes_queued_for_xmit, 0);
  global_queue_estimate = channel_get_global_queue_estimate();
  test_eq(global_queue_estimate, 512);

  /* Flush chan 1 */
  channel_flush_cells(ch1);

  /* Update and check queue sizes */
  channel_update_xmit_queue_size(ch1);
  channel_update_xmit_queue_size(ch2);
  test_eq(ch1->bytes_queued_for_xmit, 0);
  test_eq(ch2->bytes_queued_for_xmit, 0);
  global_queue_estimate = channel_get_global_queue_estimate();
  test_eq(global_queue_estimate, 0);

  /* Now block again */
  test_chan_accept_cells = 0;

  /* Queue some cells */
  cell = tor_malloc_zero(sizeof(cell_t));
  make_fake_cell(cell);
  channel_write_cell(ch1, cell);

  cell = tor_malloc_zero(sizeof(cell_t));
  make_fake_cell(cell);
  channel_write_cell(ch2, cell);

  /* Check the estimates */
  channel_update_xmit_queue_size(ch1);
  channel_update_xmit_queue_size(ch2);
  test_eq(ch1->bytes_queued_for_xmit, 512);
  test_eq(ch2->bytes_queued_for_xmit, 512);
  global_queue_estimate = channel_get_global_queue_estimate();
  test_eq(global_queue_estimate, 1024);

  /* Now close channel 2; it should be subtracted from the global queue */
  MOCK(scheduler_release_channel, scheduler_release_channel_mock);
  channel_mark_for_close(ch2);
  UNMOCK(scheduler_release_channel);

  global_queue_estimate = channel_get_global_queue_estimate();
  test_eq(global_queue_estimate, 512);

  /* Now free everything */
  MOCK(scheduler_release_channel, scheduler_release_channel_mock);
  channel_free_all();
  UNMOCK(scheduler_release_channel);

 done:
  tor_free(ch1);
  tor_free(ch2);

  return;
}

static void
test_channel_queue_size(void *arg)
{
  channel_t *ch = NULL;
  cell_t *cell = NULL;
  int n, old_count;
  uint64_t global_queue_estimate;

  (void)arg;

  ch = new_fake_channel();
  test_assert(ch);

  /* Initial queue size update */
  channel_update_xmit_queue_size(ch);
  test_eq(ch->bytes_queued_for_xmit, 0);
  global_queue_estimate = channel_get_global_queue_estimate();
  test_eq(global_queue_estimate, 0);

  /* Test the call-through to our fake lower layer */
  n = channel_num_cells_writeable(ch);
  /* chan_test_num_cells_writeable() always returns 32 */
  test_eq(n, 32);

  /*
   * Now we queue some cells and check that channel_num_cells_writeable()
   * adjusts properly
   */

  /* tell it not to accept cells */
  test_chan_accept_cells = 0;
  /* ...and keep it from trying to flush the queue */
  ch->state = CHANNEL_STATE_MAINT;

  /* Get a fresh cell */
  cell = tor_malloc_zero(sizeof(cell_t));
  make_fake_cell(cell);

  old_count = test_cells_written;
  channel_write_cell(ch, cell);
  /* Assert that it got queued, not written through, correctly */
  test_eq(test_cells_written, old_count);

  /* Now check chan_test_num_cells_writeable() again */
  n = channel_num_cells_writeable(ch);
  test_eq(n, 0); /* Should return 0 since we're in CHANNEL_STATE_MAINT */

  /* Update queue size estimates */
  channel_update_xmit_queue_size(ch);
  /* One cell, times an overhead factor of 1.0 */
  test_eq(ch->bytes_queued_for_xmit, 512);
  /* Try a different overhead factor */
  test_overhead_estimate = 0.5f;
  /* This one should be ignored since it's below 1.0 */
  channel_update_xmit_queue_size(ch);
  test_eq(ch->bytes_queued_for_xmit, 512);
  /* Now try a larger one */
  test_overhead_estimate = 2.0f;
  channel_update_xmit_queue_size(ch);
  test_eq(ch->bytes_queued_for_xmit, 1024);
  /* Go back to 1.0 */
  test_overhead_estimate = 1.0f;
  channel_update_xmit_queue_size(ch);
  test_eq(ch->bytes_queued_for_xmit, 512);
  /* Check the global estimate too */
  global_queue_estimate = channel_get_global_queue_estimate();
  test_eq(global_queue_estimate, 512);

  /* Go to open */
  old_count = test_cells_written;
  channel_change_state(ch, CHANNEL_STATE_OPEN);

  /*
   * It should try to write, but we aren't accepting cells right now, so
   * it'll requeue
   */
  test_eq(test_cells_written, old_count);

  /* Check the queue size again */
  channel_update_xmit_queue_size(ch);
  test_eq(ch->bytes_queued_for_xmit, 512);
  global_queue_estimate = channel_get_global_queue_estimate();
  test_eq(global_queue_estimate, 512);

  /*
   * Now the cell is in the queue, and we're open, so we should get 31
   * writeable cells.
   */
  n = channel_num_cells_writeable(ch);
  test_eq(n, 31);

  /* Accept cells again */
  test_chan_accept_cells = 1;
  /* ...and re-process the queue */
  old_count = test_cells_written;
  channel_flush_cells(ch);
  test_eq(test_cells_written, old_count + 1);

  /* Should have 32 writeable now */
  n = channel_num_cells_writeable(ch);
  test_eq(n, 32);

  /* Should have queue size estimate of zero */
  channel_update_xmit_queue_size(ch);
  test_eq(ch->bytes_queued_for_xmit, 0);
  global_queue_estimate = channel_get_global_queue_estimate();
  test_eq(global_queue_estimate, 0);

  /* Okay, now we're done with this one */
  MOCK(scheduler_release_channel, scheduler_release_channel_mock);
  channel_mark_for_close(ch);
  UNMOCK(scheduler_release_channel);

 done:
  tor_free(ch);

  return;
}

static void
test_channel_write(void *arg)
{
  channel_t *ch = NULL;
  cell_t *cell = tor_malloc_zero(sizeof(cell_t));
  packed_cell_t *packed_cell = NULL;
  var_cell_t *var_cell =
    tor_malloc_zero(sizeof(var_cell_t) + CELL_PAYLOAD_SIZE);
  int old_count;

  (void)arg;

  init_cell_pool();

  packed_cell = packed_cell_new();
  test_assert(packed_cell);

  ch = new_fake_channel();
  test_assert(ch);
  make_fake_cell(cell);
  make_fake_var_cell(var_cell);

  /* Tell it to accept cells */
  test_chan_accept_cells = 1;

  old_count = test_cells_written;
  channel_write_cell(ch, cell);
  test_assert(test_cells_written == old_count + 1);

  channel_write_var_cell(ch, var_cell);
  test_assert(test_cells_written == old_count + 2);

  channel_write_packed_cell(ch, packed_cell);
  test_assert(test_cells_written == old_count + 3);

  /* Now we test queueing; tell it not to accept cells */
  test_chan_accept_cells = 0;
  /* ...and keep it from trying to flush the queue */
  ch->state = CHANNEL_STATE_MAINT;

  /* Get a fresh cell */
  cell = tor_malloc_zero(sizeof(cell_t));
  make_fake_cell(cell);

  old_count = test_cells_written;
  channel_write_cell(ch, cell);
  test_assert(test_cells_written == old_count);

  /*
   * Now change back to open with channel_change_state() and assert that it
   * gets drained from the queue.
   */
  test_chan_accept_cells = 1;
  channel_change_state(ch, CHANNEL_STATE_OPEN);
  test_assert(test_cells_written == old_count + 1);

  /*
   * Check the note destroy case
   */
  cell = tor_malloc_zero(sizeof(cell_t));
  make_fake_cell(cell);
  cell->command = CELL_DESTROY;

  /* Set up the mock */
  MOCK(channel_note_destroy_not_pending,
       channel_note_destroy_not_pending_mock);

  old_count = test_destroy_not_pending_calls;
  channel_write_cell(ch, cell);
  test_assert(test_destroy_not_pending_calls == old_count + 1);

  /* Now send a non-destroy and check we don't call it */
  cell = tor_malloc_zero(sizeof(cell_t));
  make_fake_cell(cell);
  channel_write_cell(ch, cell);
  test_assert(test_destroy_not_pending_calls == old_count + 1);

  UNMOCK(channel_note_destroy_not_pending);

  /*
   * Now switch it to CLOSING so we can test the discard-cells case
   * in the channel_write_*() functions.
   */
  MOCK(scheduler_release_channel, scheduler_release_channel_mock);
  channel_mark_for_close(ch);
  UNMOCK(scheduler_release_channel);

  /* Send cells that will drop in the closing state */
  old_count = test_cells_written;

  cell = tor_malloc_zero(sizeof(cell_t));
  make_fake_cell(cell);
  channel_write_cell(ch, cell);
  test_assert(test_cells_written == old_count);

  var_cell = tor_malloc_zero(sizeof(var_cell_t) + CELL_PAYLOAD_SIZE);
  make_fake_var_cell(var_cell);
  channel_write_var_cell(ch, var_cell);
  test_assert(test_cells_written == old_count);

  packed_cell = packed_cell_new();
  channel_write_packed_cell(ch, packed_cell);
  test_assert(test_cells_written == old_count);

  free_cell_pool();

 done:
  tor_free(ch);

  return;
}

struct testcase_t channel_tests[] = {
  { "multi", test_channel_multi, TT_FORK, NULL, NULL },
  { "queue_size", test_channel_queue_size, TT_FORK, NULL, NULL },
  { "write", test_channel_write, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};

