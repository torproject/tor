/* * Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file scheduler.h
 * \brief Header file for scheduler.c
 **/

#ifndef TOR_SCHEDULER_H
#define TOR_SCHEDULER_H

#include "or.h"
#include "channel.h"
#include "testsupport.h"

/* Global-visibility scheduler functions */

/* Set up and shut down the scheduler from main.c */
void scheduler_free_all(void);
void scheduler_init(void);
void scheduler_run(void);

/* Mark channels as having cells or wanting/not wanting writes */
void scheduler_channel_doesnt_want_writes(channel_t *chan);
void scheduler_channel_has_waiting_cells(channel_t *chan);
void scheduler_channel_wants_writes(channel_t *chan);

/* Notify the scheduler of a channel being closed */
MOCK_DECL(void,scheduler_release_channel,(channel_t *chan));

/* Notify scheduler of queue size adjustments */
void scheduler_adjust_queue_size(channel_t *chan, char dir, uint64_t adj);

/* Notify scheduler that a channel's queue position may have changed */
void scheduler_touch_channel(channel_t *chan);

#endif /* !defined(TOR_SCHEDULER_H) */

