/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file mqueue.c
 *
 * \brief Message-queue structure based on a pair of dynamic arrays.
 **/

#include "orconfig.h"
#include "lib/malloc/malloc.h"
#include "lib/container/mqueue.h"
#include "lib/container/smartlist.h"

/** Initialize a mqueue_t structure. */
void
mqueue_init(mqueue_t *mq)
{
  mq->flushing = smartlist_new();
  mq->filling = smartlist_new();
}

/** Clear a mqueue_t structure.  Does not free the items held in the queue. */
void
mqueue_clear(mqueue_t *mq)
{
  smartlist_free(mq->flushing);
  smartlist_free(mq->filling);
}

/** Run <b>fn</b> on every element of <b>mq</b>, passing it <b>arg</b> as a
 * second argument.
 *
 * Items are processed from the front of the queue to the end.
 **/
void
mqueue_foreach(mqueue_t *mq, void (*fn)(void *, void *), void *userarg)
{
  for (int i = smartlist_len(mq->flushing)-1; i >= 0; --i) {
    void *item = smartlist_get(mq->flushing, i);
    fn(item, userarg);
  }
  SMARTLIST_FOREACH(mq->filling, void *, item, fn(item, userarg));
}

/** Return the number of elements stored in <b>mq</b>. */
size_t
mqueue_len(const mqueue_t *mq)
{
  size_t n = smartlist_len(mq->flushing);
  n += smartlist_len(mq->filling);
  return n;
}

/** Append <b>item</b> to the end of <b>mq</b>. */
void
mqueue_push(mqueue_t *mq, void *item)
{
  smartlist_add(mq->filling, item);
}

/** Remove and return the first item in <b>mq</b>.  Return NULL if <b>mq</b>
 * is empty. */
void *
mqueue_pop(mqueue_t *mq)
{
  if (smartlist_len(mq->flushing) == 0) {
    smartlist_t *tmp = mq->flushing;
    mq->flushing = mq->filling;
    mq->filling = tmp;
    smartlist_reverse(mq->flushing);
  }

  return smartlist_pop_last(mq->flushing);
}
