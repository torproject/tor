/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define DISPATCH_PRIVATE
#include "orconfig.h"

#include "lib/dispatch/dispatch_core.h"
#include "lib/dispatch/dispatch_st.h"
#include "lib/dispatch/msg.h"
#include "lib/dispatch/msgtypes.h"
#include "lib/dispatch/namemap.h"

#include "lib/container/mqueue.h"
#include "lib/malloc/malloc.h"
#include "lib/log/util_bug.h"

#include <string.h>

/**
 * Use <b>d</b> to drop all storage held for <b>msg</b>.
 *
 * (We need the dispatcher so we know how to free the auxiliary data.)
 **/
void
dispatcher_free_msg_(const dispatcher_t *d, msg_t *msg)
{
  if (!msg)
    return;

  d->typefns[msg->type].free_fn(msg->aux_data__);
  tor_free(msg);
}

/**
 * Callback to use with mqueue_foreach() to free all the messages in a queue.
 **/
static void
msg_free_mqueue_cb_(void *msg_, void *dispatcher_)
{
  const dispatcher_t *dispatcher = dispatcher_;
  msg_t *msg = msg_;
  dispatcher_free_msg_(dispatcher, msg);
}

/**
 * Free the pointer to <b>d</b> for every configured pub_binding_t.
 *
 * Used when we are about to free <b>d</b>, so that nobody can publish to it
 * any more.
 **/
static void
dispatch_clear_pub_binding_backptrs(dispatcher_t *d)
{
  SMARTLIST_FOREACH_BEGIN(d->cfg->items, pubsub_cfg_t *, cfg) {
    if (cfg->pub_binding) {
      cfg->pub_binding->dispatch_ptr = NULL;
    }
  } SMARTLIST_FOREACH_END(cfg);
}

/**
 * Release all storage held by <b>d</b>.
 **/
void
dispatcher_free_(dispatcher_t *d)
{
  if (d == NULL)
    return;

  dispatch_clear_pub_binding_backptrs(d);

  size_t n_queues = d->n_queues;
  for (size_t i = 0; i < n_queues; ++i) {
    mqueue_foreach(&d->queues[i].queue, msg_free_mqueue_cb_, d);
    mqueue_clear(&d->queues[i].queue);
  }

  size_t n_msgs = d->n_msgs;

  for (size_t i = 0; i < n_msgs; ++i) {
    tor_free(d->table[i].more_fns);
  }
  tor_free(d->table);
  tor_free(d->typefns);
  tor_free(d->queues);

  // This is the only time we will treat d->cfg as non-const.
  dispatch_cfg_free_((dispatch_cfg_t *) d->cfg);

  tor_free(d);
}

/**
 * Tell the dispatcher to call <b>fn</b> with <b>userdata</b> whenever
 * <b>chan</b> becomes nonempty.  Return 0 on success, -1 on error.
 **/
int
dispatcher_set_alert_fn(dispatcher_t *d, channel_id_t chan,
                        dispatch_alertfn_t fn, void *userdata)
{
  if (BUG(chan >= d->n_queues))
    return -1;

  dispatch_queue_t *q = &d->queues[chan];
  q->alert_fn = fn;
  q->alert_fn_arg = userdata;
  return 0;
}

/**
 * Publish a message from the publication binding <b>pub</b> using the
 * auxiliary data <b>auxdata</b>.
 *
 * Return 0 on success, -1 on failure.
 **/
int
dispatch_pub_(const pub_binding_t *pub, msg_aux_data_t auxdata)
{
  dispatcher_t *d = pub->dispatch_ptr;
  if (BUG(! d)) {
    /* Tried to publish a message before the dispatcher was configured. */
    /* (Without a dispatcher, we don't know how to free auxdata.) */
    return -1;
  }

  if (BUG(pub->msg_template.type >= d->n_types)) {
    /* The type associated with this message is not known to the dispatcher. */
    /* (Without a correct type, we don't know how to free auxdata.) */
    return -1;
  }

  if (BUG(pub->msg_template.msg >= d->n_msgs) ||
      BUG(pub->msg_template.channel >= d->n_queues)) {
    /* The message ID or channel ID was out of bounds. */
    d->typefns[pub->msg_template.type].free_fn(auxdata);
    return -1;
  }

  if (!d->table[pub->msg_template.msg].n_enabled) {
    /* Fast path: nobody wants this data. */

    // XXXX Faster path: we could store this in the pub_binding_t.
    d->typefns[pub->msg_template.type].free_fn(auxdata);
    return 0;
  }

  /* Construct the message object */
  msg_t *m = tor_malloc(sizeof(msg_t));
  memcpy(m, &pub->msg_template, sizeof(msg_t));
  m->aux_data__ = auxdata;

  /* Find the right queue. */
  dispatch_queue_t *q = &d->queues[m->channel];
  bool was_empty = mqueue_len(&q->queue) == 0;

  /* Append the message. */
  mqueue_push(&q->queue, m);

  /* If we just made the queue nonempty for the first time, call the alert
   * function. */
  if (was_empty) {
    q->alert_fn(d, m->channel, q->alert_fn_arg);
  }

  return 0;
}

/**
 * Run all of the callbacks on <b>d</b> associated with <b>m</b>.
 **/
static void
dispatcher_run_msg_cbs(const dispatcher_t *d, msg_t *m)
{
  tor_assert(m->msg <= d->n_msgs);
  dispatch_table_entry_t *ent = &d->table[m->msg];
  int n_fns = ent->n_fns;

  int i;
  for (i=0; i < N_FAST_FNS && i < n_fns; ++i) {
    ent->fns[i](m);
  }
  for ( ; i < n_fns; ++i) {
    ent->more_fns[i-N_FAST_FNS](m);
  }
}

/**
 * Run up to <b>max_msgs</b> callbacks for messages on the channel <b>ch</b>
 * on the given dispatcher.  Return 0 on success or recoverable failure,
 * -1 on unrecoverable error.
 **/
int
dispatch_flush(dispatcher_t *d, channel_id_t ch, int max_msgs)
{
  if (BUG(ch >= d->n_queues))
    return 0;

  int n_flushed = 0;
  dispatch_queue_t *q = &d->queues[ch];

  while (n_flushed < max_msgs) {
    msg_t *m = mqueue_pop(&q->queue);
    if (!m)
      break;
    dispatcher_run_msg_cbs(d, m);
    dispatcher_free_msg(d, m);
    ++n_flushed;
  }

  return 0;
}
