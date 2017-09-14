/* * Copyright (c) 2013-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "config.h"

#include "compat_libevent.h"
#define SCHEDULER_PRIVATE_
#include "scheduler.h"

#include <event2/event.h>

/**
 * \file scheduler.c
 * \brief Channel scheduling system: decides which channels should send and
 * receive when.
 *
 * This module is the global/common parts of the scheduling system. This system
 * is what decides what channels get to send cells on their circuits and when.
 *
 * Terms:
 * - "Scheduling system": the collection of scheduler*.{h,c} files and their
 *   aggregate behavior.
 * - "Scheduler implementation": a scheduler_t. The scheduling system has one
 *   active scheduling implementation at a time.
 *
 * In this file you will find state that any scheduler implmentation can have
 * access to as well as the functions the rest of Tor uses to interact with the
 * scheduling system.
 *
 * The earliest versions of Tor approximated a kind of round-robin system
 * among active connections, but only approximated it. It would only consider
 * one connection (roughly equal to a channel in today's terms) at a time, and
 * thus could only prioritize circuits against others on the same connection.
 *
 * Then in response to the KIST paper[0], Tor implemented a global
 * circuit scheduler. It was supposed to prioritize circuits across man
 * channels, but wasn't effective. It is preserved in scheduler_vanilla.c.
 *
 * [0]: http://www.robgjansen.com/publications/kist-sec2014.pdf
 *
 * Then we actually got around to implementing KIST for real. We decided to
 * modularize the scheduler so new ones can be implemented. You can find KIST
 * in scheduler_kist.c.
 *
 * Channels have one of four scheduling states based on whether or not they
 * have cells to send and whether or not they are able to send.
 *
 * <ol>
 * <li>
 *   Not open for writes, no cells to send.
 *     <ul><li> Not much to do here, and the channel will have scheduler_state
 *       == SCHED_CHAN_IDLE
 *     <li> Transitions from:
 *       <ul>
 *       <li>Open for writes/has cells by simultaneously draining all circuit
 *         queues and filling the output buffer.
 *       </ul>
 *     <li> Transitions to:
 *      <ul>
 *       <li> Not open for writes/has cells by arrival of cells on an attached
 *         circuit (this would be driven from append_cell_to_circuit_queue())
 *       <li> Open for writes/no cells by a channel type specific path;
 *         driven from connection_or_flushed_some() for channel_tls_t.
 *      </ul>
 *    </ul>
 *
 * <li> Open for writes, no cells to send
 *   <ul>
 *     <li>Not much here either; this will be the state an idle but open
 *       channel can be expected to settle in.  It will have scheduler_state
 *       == SCHED_CHAN_WAITING_FOR_CELLS
 *     <li> Transitions from:
 *       <ul>
 *       <li>Not open for writes/no cells by flushing some of the output
 *         buffer.
 *       <li>Open for writes/has cells by the scheduler moving cells from
 *         circuit queues to channel output queue, but not having enough
 *         to fill the output queue.
 *       </ul>
 *     <li> Transitions to:
 *       <ul>
 *        <li>Open for writes/has cells by arrival of new cells on an attached
 *         circuit, in append_cell_to_circuit_queue()
 *       </ul>
 *     </ul>
 *
 * <li>Not open for writes, cells to send
 *     <ul>
 *     <li>This is the state of a busy circuit limited by output bandwidth;
 *       cells have piled up in the circuit queues waiting to be relayed.
 *       The channel will have scheduler_state == SCHED_CHAN_WAITING_TO_WRITE.
 *     <li> Transitions from:
 *       <ul>
 *       <li>Not open for writes/no cells by arrival of cells on an attached
 *         circuit
 *       <li> Open for writes/has cells by filling an output buffer without
 *         draining all cells from attached circuits
 *       </ul>
 *    <li> Transitions to:
 *       <ul>
 *       <li>Opens for writes/has cells by draining some of the output buffer
 *         via the connection_or_flushed_some() path (for channel_tls_t).
 *       </ul>
 *    </ul>
 *
 * <li>Open for writes, cells to send
 *     <ul>
 *     <li>This connection is ready to relay some cells and waiting for
 *       the scheduler to choose it.  The channel will have scheduler_state ==
 *       SCHED_CHAN_PENDING.
 *     <li>Transitions from:
 *       <ul>
 *       <li> Not open for writes/has cells by the connection_or_flushed_some()
 *         path
 *       <li> Open for writes/no cells by the append_cell_to_circuit_queue()
 *         path
 *       </ul>
 *     <li> Transitions to:
 *       <ul>
 *        <li>Not open for writes/no cells by draining all circuit queues and
 *          simultaneously filling the output buffer.
 *        <li>Not open for writes/has cells by writing enough cells to fill the
 *         output buffer
 *        <li>Open for writes/no cells by draining all attached circuit queues
 *         without also filling the output buffer
 *       </ul>
 *    </ul>
 * </ol>
 *
 * Other event-driven parts of the code move channels between these scheduling
 * states by calling scheduler functions. The scheduling system builds up a
 * list of channels in the SCHED_CHAN_PENDING state that the scheduler
 * implementation should then use when it runs. Scheduling implementations need
 * to properly update channel states during their scheduler_t->run() function
 * as that is the only opportunity for channels to move from SCHED_CHAN_PENDING
 * to any other state.
 *
 * The remainder of this file is a small amount of state that any scheduler
 * implementation should have access to, and the functions the rest of Tor uses
 * to interact with the scheduling system.
 */

/*****************************************************************************
 * Scheduling system state
 *
 * State that can be accessed from any scheduler implementation (but not
 * outside the scheduling system)
 *****************************************************************************/

STATIC scheduler_t *the_scheduler;

/*
 * We keep a list of channels that are pending - i.e, have cells to write
 * and can accept them to send. The enum scheduler_state in channel_t
 * is reserved for our use.
 *
 * Priority queue of channels that can write and have cells (pending work)
 */
STATIC smartlist_t *channels_pending = NULL;

/*
 * This event runs the scheduler from its callback, and is manually
 * activated whenever a channel enters open for writes/cells to send.
 */
STATIC struct event *run_sched_ev = NULL;

/*****************************************************************************
 * Scheduling system static function definitions
 *
 * Functions that can only be accessed from this file.
 *****************************************************************************/

/*
 * Scheduler event callback; this should get triggered once per event loop
 * if any scheduling work was created during the event loop.
 */
static void
scheduler_evt_callback(evutil_socket_t fd, short events, void *arg)
{
  (void) fd;
  (void) events;
  (void) arg;

  log_debug(LD_SCHED, "Scheduler event callback called");

  /* Run the scheduler. This is a mandatory function. */

  /* We might as well assert on this. If this function doesn't exist, no cells
   * are getting scheduled. Things are very broken. scheduler_t says the run()
   * function is mandatory. */
  tor_assert(the_scheduler->run);
  the_scheduler->run();

  /* Schedule itself back in if it has more work. */

  /* Again, might as well assert on this mandatory scheduler_t function. If it
   * doesn't exist, there's no way to tell libevent to run the scheduler again
   * in the future. */
  tor_assert(the_scheduler->schedule);
  the_scheduler->schedule();
}

/*****************************************************************************
 * Scheduling system private function definitions
 *
 * Functions that can only be accessed from scheduler*.c
 *****************************************************************************/

/* Return the pending channel list. */
smartlist_t *
get_channels_pending(void)
{
  return channels_pending;
}

/* Return our libevent scheduler event. */
struct event *
get_run_sched_ev(void)
{
  return run_sched_ev;
}

/* Comparison function to use when sorting pending channels */
MOCK_IMPL(int,
scheduler_compare_channels, (const void *c1_v, const void *c2_v))
{
  const channel_t *c1 = NULL, *c2 = NULL;
  /* These are a workaround for -Wbad-function-cast throwing a fit */
  const circuitmux_policy_t *p1, *p2;
  uintptr_t p1_i, p2_i;

  c1 = (const channel_t *)(c1_v);
  c2 = (const channel_t *)(c2_v);

  IF_BUG_ONCE(!c1 || !c2) {
    if (c1 && !c2) {
      return -1;
    } else if (c2 && !c1) {
      return 1;
    } else {
      return -1;
    }
  }

  if (c1 != c2) {
    if (circuitmux_get_policy(c1->cmux) ==
        circuitmux_get_policy(c2->cmux)) {
      /* Same cmux policy, so use the mux comparison */
      return circuitmux_compare_muxes(c1->cmux, c2->cmux);
    } else {
      /*
       * Different policies; not important to get this edge case perfect
       * because the current code never actually gives different channels
       * different cmux policies anyway.  Just use this arbitrary but
       * definite choice.
       */
      p1 = circuitmux_get_policy(c1->cmux);
      p2 = circuitmux_get_policy(c2->cmux);
      p1_i = (uintptr_t)p1;
      p2_i = (uintptr_t)p2;

      return (p1_i < p2_i) ? -1 : 1;
    }
  } else {
    /* c1 == c2, so always equal */
    return 0;
  }
}

/*****************************************************************************
 * Scheduling system global functions
 *
 * Functions that can be accessed from anywhere in Tor.
 *****************************************************************************/

/* Using the global options, select the scheduler we should be using. */
static void
select_scheduler(void)
{
  const char *chosen_sched_type = NULL;

  /* This list is ordered that is first entry has the first priority. Thus, as
   * soon as we find a scheduler type that we can use, we use it and stop. */
  SMARTLIST_FOREACH_BEGIN(get_options()->SchedulerTypes_, int *, type) {
    switch (*type) {
    case SCHEDULER_VANILLA:
      the_scheduler = get_vanilla_scheduler();
      chosen_sched_type = "Vanilla";
      goto end;
    case SCHEDULER_KIST:
      if (!scheduler_can_use_kist()) {
        log_warn(LD_SCHED, "Scheduler KIST can't be used. Consider removing "
                           "it from Schedulers or if you have a tor built "
                           "with KIST support, you should make sure "
                           "KISTSchedRunInterval is a non zero value");
        continue;
      }
      the_scheduler = get_kist_scheduler();
      chosen_sched_type = "KIST";
      scheduler_kist_set_full_mode();
      goto end;
    case SCHEDULER_KIST_LITE:
      chosen_sched_type = "KISTLite";
      the_scheduler = get_kist_scheduler();
      scheduler_kist_set_lite_mode();
      goto end;
    default:
      /* Our option validation should have caught this. */
      tor_assert_unreached();
    }
  } SMARTLIST_FOREACH_END(type);

 end:
  log_notice(LD_CONFIG, "Scheduler type %s has been enabled.",
             chosen_sched_type);
}

/*
 * Little helper function called from a few different places. It changes the
 * scheduler implementation, if necessary. And if it did, it then tells the
 * old one to free its state and the new one to initialize.
 */
static void
set_scheduler(void)
{
  scheduler_t *old_scheduler = the_scheduler;

  /* From the options, select the scheduler type to set. */
  select_scheduler();

  if (old_scheduler != the_scheduler) {
    /* Allow the old scheduler to clean up, if needed. */
    if (old_scheduler && old_scheduler->free_all) {
      old_scheduler->free_all();
    }
    /* We don't clean up the old scheduler_t. We keep any type of scheduler
     * we've allocated so we can do an easy switch back. */

    /* Initialize the new scheduler. */
    if (the_scheduler->init) {
      the_scheduler->init();
    }
  }
}

/*
 * This is how the scheduling system is notified of Tor's configuration
 * changing. For example: a SIGHUP was issued.
 */
void
scheduler_conf_changed(void)
{
  /* Let the scheduler decide what it should do. */
  set_scheduler();

  /* Then tell the (possibly new) scheduler that we have new options. */
  if (the_scheduler->on_new_options) {
    the_scheduler->on_new_options();
  }
}

/*
 * Whenever we get a new consensus, this function is called.
 */
void
scheduler_notify_networkstatus_changed(const networkstatus_t *old_c,
                                       const networkstatus_t *new_c)
{
  /* Then tell the (possibly new) scheduler that we have a new consensus */
  if (the_scheduler->on_new_consensus) {
    the_scheduler->on_new_consensus(old_c, new_c);
  }
  /* Maybe the consensus param made us change the scheduler. */
  set_scheduler();
}

/*
 * Free everything scheduling-related from main.c. Note this is only called
 * when Tor is shutting down, while scheduler_t->free_all() is called both when
 * Tor is shutting down and when we are switching schedulers.
 */
void
scheduler_free_all(void)
{
  log_debug(LD_SCHED, "Shutting down scheduler");

  if (run_sched_ev) {
    if (event_del(run_sched_ev) < 0) {
      log_warn(LD_BUG, "Problem deleting run_sched_ev");
    }
    tor_event_free(run_sched_ev);
    run_sched_ev = NULL;
  }

  if (channels_pending) {
    /* We don't have ownership of the object in this list. */
    smartlist_free(channels_pending);
    channels_pending = NULL;
  }

  if (the_scheduler && the_scheduler->free_all) {
    the_scheduler->free_all();
  }
  tor_free(the_scheduler);
  the_scheduler = NULL;
}

/** Mark a channel as no longer ready to accept writes */

MOCK_IMPL(void,
scheduler_channel_doesnt_want_writes,(channel_t *chan))
{
  IF_BUG_ONCE(!chan) {
    return;
  }
  IF_BUG_ONCE(!channels_pending) {
    return;
  }

  /* If it's already in pending, we can put it in waiting_to_write */
  if (chan->scheduler_state == SCHED_CHAN_PENDING) {
    /*
     * It's in channels_pending, so it shouldn't be in any of
     * the other lists.  It can't write any more, so it goes to
     * channels_waiting_to_write.
     */
    smartlist_pqueue_remove(channels_pending,
                            scheduler_compare_channels,
                            offsetof(channel_t, sched_heap_idx),
                            chan);
    chan->scheduler_state = SCHED_CHAN_WAITING_TO_WRITE;
    log_debug(LD_SCHED,
              "Channel " U64_FORMAT " at %p went from pending "
              "to waiting_to_write",
              U64_PRINTF_ARG(chan->global_identifier), chan);
  } else {
    /*
     * It's not in pending, so it can't become waiting_to_write; it's
     * either not in any of the lists (nothing to do) or it's already in
     * waiting_for_cells (remove it, can't write any more).
     */
    if (chan->scheduler_state == SCHED_CHAN_WAITING_FOR_CELLS) {
      chan->scheduler_state = SCHED_CHAN_IDLE;
      log_debug(LD_SCHED,
                "Channel " U64_FORMAT " at %p left waiting_for_cells",
                U64_PRINTF_ARG(chan->global_identifier), chan);
    }
  }
}

/** Mark a channel as having waiting cells */

MOCK_IMPL(void,
scheduler_channel_has_waiting_cells,(channel_t *chan))
{
  IF_BUG_ONCE(!chan) {
    return;
  }
  IF_BUG_ONCE(!channels_pending) {
    return;
  }

  /* First, check if this one also writeable */
  if (chan->scheduler_state == SCHED_CHAN_WAITING_FOR_CELLS) {
    /*
     * It's in channels_waiting_for_cells, so it shouldn't be in any of
     * the other lists.  It has waiting cells now, so it goes to
     * channels_pending.
     */
    chan->scheduler_state = SCHED_CHAN_PENDING;
    smartlist_pqueue_add(channels_pending,
                         scheduler_compare_channels,
                         offsetof(channel_t, sched_heap_idx),
                         chan);
    log_debug(LD_SCHED,
              "Channel " U64_FORMAT " at %p went from waiting_for_cells "
              "to pending",
              U64_PRINTF_ARG(chan->global_identifier), chan);
    /* If we made a channel pending, we potentially have scheduling work to
     * do. */
    the_scheduler->schedule();
  } else {
    /*
     * It's not in waiting_for_cells, so it can't become pending; it's
     * either not in any of the lists (we add it to waiting_to_write)
     * or it's already in waiting_to_write or pending (we do nothing)
     */
    if (!(chan->scheduler_state == SCHED_CHAN_WAITING_TO_WRITE ||
          chan->scheduler_state == SCHED_CHAN_PENDING)) {
      chan->scheduler_state = SCHED_CHAN_WAITING_TO_WRITE;
      log_debug(LD_SCHED,
                "Channel " U64_FORMAT " at %p entered waiting_to_write",
                U64_PRINTF_ARG(chan->global_identifier), chan);
    }
  }
}

/*
 * Initialize everything scheduling-related from config.c. Note this is only
 * called when Tor is starting up, while scheduler_t->init() is called both
 * when Tor is starting up and when we are switching schedulers.
 */
void
scheduler_init(void)
{
  log_debug(LD_SCHED, "Initting scheduler");

  // Two '!' because we really do want to check if the pointer is non-NULL
  IF_BUG_ONCE(!!run_sched_ev) {
    log_warn(LD_SCHED, "We should not already have a libevent scheduler event."
             "I'll clean the old one up, but this is odd.");
    tor_event_free(run_sched_ev);
    run_sched_ev = NULL;
  }
  run_sched_ev = tor_event_new(tor_libevent_get_base(), -1,
                               0, scheduler_evt_callback, NULL);
  channels_pending = smartlist_new();

  set_scheduler();
}

/*
 * If a channel is going away, this is how the scheduling system is informed
 * so it can do any freeing necessary. This ultimately calls
 * scheduler_t->on_channel_free() so the current scheduler can release any
 * state specific to this channel.
 */
MOCK_IMPL(void,
scheduler_release_channel,(channel_t *chan))
{
  IF_BUG_ONCE(!chan) {
    return;
  }
  IF_BUG_ONCE(!channels_pending) {
    return;
  }

  if (chan->scheduler_state == SCHED_CHAN_PENDING) {
    if (smartlist_pos(channels_pending, chan) == -1) {
      log_warn(LD_SCHED, "Scheduler asked to release channel %" PRIu64 " "
                         "but it wasn't in channels_pending",
               chan->global_identifier);
    } else {
      smartlist_pqueue_remove(channels_pending,
                              scheduler_compare_channels,
                              offsetof(channel_t, sched_heap_idx),
                              chan);
    }
  }

  if (the_scheduler->on_channel_free) {
    the_scheduler->on_channel_free(chan);
  }
  chan->scheduler_state = SCHED_CHAN_IDLE;
}

/** Mark a channel as ready to accept writes */

void
scheduler_channel_wants_writes(channel_t *chan)
{
  IF_BUG_ONCE(!chan) {
    return;
  }
  IF_BUG_ONCE(!channels_pending) {
    return;
  }

  /* If it's already in waiting_to_write, we can put it in pending */
  if (chan->scheduler_state == SCHED_CHAN_WAITING_TO_WRITE) {
    /*
     * It can write now, so it goes to channels_pending.
     */
    log_debug(LD_SCHED, "chan=%" PRIu64 " became pending",
        chan->global_identifier);
    smartlist_pqueue_add(channels_pending,
                         scheduler_compare_channels,
                         offsetof(channel_t, sched_heap_idx),
                         chan);
    chan->scheduler_state = SCHED_CHAN_PENDING;
    log_debug(LD_SCHED,
              "Channel " U64_FORMAT " at %p went from waiting_to_write "
              "to pending",
              U64_PRINTF_ARG(chan->global_identifier), chan);
    /* We just made a channel pending, we have scheduling work to do. */
    the_scheduler->schedule();
  } else {
    /*
     * It's not in SCHED_CHAN_WAITING_TO_WRITE, so it can't become pending;
     * it's either idle and goes to WAITING_FOR_CELLS, or it's a no-op.
     */
    if (!(chan->scheduler_state == SCHED_CHAN_WAITING_FOR_CELLS ||
          chan->scheduler_state == SCHED_CHAN_PENDING)) {
      chan->scheduler_state = SCHED_CHAN_WAITING_FOR_CELLS;
      log_debug(LD_SCHED,
                "Channel " U64_FORMAT " at %p entered waiting_for_cells",
                U64_PRINTF_ARG(chan->global_identifier), chan);
    }
  }
}

#ifdef TOR_UNIT_TESTS

/*
 * Notify scheduler that a channel's queue position may have changed.
 */
void
scheduler_touch_channel(channel_t *chan)
{
  IF_BUG_ONCE(!chan) {
    return;
  }

  if (chan->scheduler_state == SCHED_CHAN_PENDING) {
    /* Remove and re-add it */
    smartlist_pqueue_remove(channels_pending,
                            scheduler_compare_channels,
                            offsetof(channel_t, sched_heap_idx),
                            chan);
    smartlist_pqueue_add(channels_pending,
                         scheduler_compare_channels,
                         offsetof(channel_t, sched_heap_idx),
                         chan);
  }
  /* else no-op, since it isn't in the queue */
}

#endif /* TOR_UNIT_TESTS */

