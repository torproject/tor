/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_MQUEUE_H
#define TOR_MQUEUE_H

/**
 * \file mqueue.h
 *
 * \brief Header for mqueue.c
 **/

#include <stddef.h>

struct smartlist_t;
/**
 * A message queue, backed by a pair of smartlists.
 */
typedef struct mqueue_t {
  /** A list of items near the front of the queue -- they are stored
   * in reverse order, so we can pop them off the end of the array. */
  struct smartlist_t *flushing;
  /** A list of items near the end of the queue -- they are stored in
   * normal order, so we can push onto the end of the array. */
  struct smartlist_t *filling;
} mqueue_t;

void mqueue_init(mqueue_t *mq);
void mqueue_clear(mqueue_t *mq);
void mqueue_foreach(mqueue_t *mq, void (*fn)(void *, void *),
                    void *userarg);
size_t mqueue_len(const mqueue_t *mq);
void mqueue_push(mqueue_t *mq, void *item);
void *mqueue_pop(mqueue_t *mq);

#endif /* !defined(TOR_MQUEUE_H) */
