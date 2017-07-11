/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include <event2/event.h>

#include "or.h"
#include "config.h"
#define TOR_CHANNEL_INTERNAL_
#include "channel.h"
#define SCHEDULER_PRIVATE_
#include "scheduler.h"

/*****************************************************************************
 * Other internal data
 *****************************************************************************/

/* Maximum cells to flush in a single call to channel_flush_some_cells(); */
#define MAX_FLUSH_CELLS 1000

static scheduler_t *vanilla_scheduler = NULL;

/*****************************************************************************
 * Externally called function implementations
 *****************************************************************************/

/* Return true iff the scheduler has work to perform. */
static int
have_work(void)
{
  smartlist_t *cp = get_channels_pending();
  tor_assert(cp);
  return smartlist_len(cp) > 0;
}

/** Retrigger the scheduler in a way safe to use from the callback */

static void
vanilla_scheduler_schedule(void)
{
  if (!have_work()) {
    return;
  }
  struct event *ev = get_run_sched_ev();
  tor_assert(ev);
  event_active(ev, EV_TIMEOUT, 1);
}

static void
vanilla_scheduler_run(void)
{
  int n_cells, n_chans_before, n_chans_after;
  ssize_t flushed, flushed_this_time;
  smartlist_t *cp = get_channels_pending();
  smartlist_t *to_readd = NULL;
  channel_t *chan = NULL;

  log_debug(LD_SCHED, "We have a chance to run the scheduler");

  n_chans_before = smartlist_len(cp);

  while (smartlist_len(cp) > 0) {
    /* Pop off a channel */
    chan = smartlist_pqueue_pop(cp,
                                scheduler_compare_channels,
                                offsetof(channel_t, sched_heap_idx));
    tor_assert(chan);

    /* Figure out how many cells we can write */
    n_cells = channel_num_cells_writeable(chan);
    if (n_cells > 0) {
      log_debug(LD_SCHED,
                "Scheduler saw pending channel " U64_FORMAT " at %p with "
                "%d cells writeable",
                U64_PRINTF_ARG(chan->global_identifier), chan, n_cells);

      flushed = 0;
      while (flushed < n_cells) {
        flushed_this_time =
          channel_flush_some_cells(chan,
                        MIN(MAX_FLUSH_CELLS, (size_t) n_cells - flushed));
        if (flushed_this_time <= 0) break;
        flushed += flushed_this_time;
      }

      if (flushed < n_cells) {
        /* We ran out of cells to flush */
        chan->scheduler_state = SCHED_CHAN_WAITING_FOR_CELLS;
        log_debug(LD_SCHED,
                  "Channel " U64_FORMAT " at %p "
                  "entered waiting_for_cells from pending",
                  U64_PRINTF_ARG(chan->global_identifier),
                  chan);
      } else {
        /* The channel may still have some cells */
        if (channel_more_to_flush(chan)) {
        /* The channel goes to either pending or waiting_to_write */
          if (channel_num_cells_writeable(chan) > 0) {
            /* Add it back to pending later */
            if (!to_readd) to_readd = smartlist_new();
            smartlist_add(to_readd, chan);
            log_debug(LD_SCHED,
                      "Channel " U64_FORMAT " at %p "
                      "is still pending",
                      U64_PRINTF_ARG(chan->global_identifier),
                      chan);
          } else {
            /* It's waiting to be able to write more */
            chan->scheduler_state = SCHED_CHAN_WAITING_TO_WRITE;
            log_debug(LD_SCHED,
                      "Channel " U64_FORMAT " at %p "
                      "entered waiting_to_write from pending",
                      U64_PRINTF_ARG(chan->global_identifier),
                      chan);
          }
        } else {
          /* No cells left; it can go to idle or waiting_for_cells */
          if (channel_num_cells_writeable(chan) > 0) {
            /*
             * It can still accept writes, so it goes to
             * waiting_for_cells
             */
            chan->scheduler_state = SCHED_CHAN_WAITING_FOR_CELLS;
            log_debug(LD_SCHED,
                      "Channel " U64_FORMAT " at %p "
                      "entered waiting_for_cells from pending",
                      U64_PRINTF_ARG(chan->global_identifier),
                      chan);
          } else {
            /*
             * We exactly filled up the output queue with all available
             * cells; go to idle.
             */
            chan->scheduler_state = SCHED_CHAN_IDLE;
            log_debug(LD_SCHED,
                      "Channel " U64_FORMAT " at %p "
                      "become idle from pending",
                      U64_PRINTF_ARG(chan->global_identifier),
                      chan);
          }
        }
      }

      log_debug(LD_SCHED,
                "Scheduler flushed %d cells onto pending channel "
                U64_FORMAT " at %p",
                (int)flushed, U64_PRINTF_ARG(chan->global_identifier),
                chan);
    } else {
      log_info(LD_SCHED,
               "Scheduler saw pending channel " U64_FORMAT " at %p with "
               "no cells writeable",
               U64_PRINTF_ARG(chan->global_identifier), chan);
      /* Put it back to WAITING_TO_WRITE */
      chan->scheduler_state = SCHED_CHAN_WAITING_TO_WRITE;
    }
  }

  /* Readd any channels we need to */
  if (to_readd) {
    SMARTLIST_FOREACH_BEGIN(to_readd, channel_t *, readd_chan) {
      readd_chan->scheduler_state = SCHED_CHAN_PENDING;
      smartlist_pqueue_add(cp,
                           scheduler_compare_channels,
                           offsetof(channel_t, sched_heap_idx),
                           readd_chan);
    } SMARTLIST_FOREACH_END(readd_chan);
    smartlist_free(to_readd);
  }

  n_chans_after = smartlist_len(cp);
  log_debug(LD_SCHED, "Scheduler handled %d of %d pending channels",
            n_chans_before - n_chans_after, n_chans_before);
}

scheduler_t *
get_vanilla_scheduler(void)
{
  if (!vanilla_scheduler) {
    log_debug(LD_SCHED, "Initializing vanilla scheduler struct");
    vanilla_scheduler = tor_malloc_zero(sizeof(*vanilla_scheduler));
    vanilla_scheduler->free_all = NULL;
    vanilla_scheduler->on_channel_free = NULL;
    vanilla_scheduler->init = NULL;
    vanilla_scheduler->on_new_consensus = NULL;
    vanilla_scheduler->schedule = vanilla_scheduler_schedule;
    vanilla_scheduler->run = vanilla_scheduler_run;
    vanilla_scheduler->on_new_options = NULL;
  }
  return vanilla_scheduler;
}

