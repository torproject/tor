/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_WORKQUEUE_H
#define TOR_WORKQUEUE_H

#include "compat.h"

typedef struct replyqueue_s replyqueue_t;
typedef struct threadpool_s threadpool_t;
typedef struct workqueue_entry_s workqueue_entry_t;

#define WQ_CMD_RUN    0
#define WQ_CMD_CANCEL 1

#define WQ_RPL_REPLY    0
#define WQ_RPL_ERROR    1
#define WQ_RPL_SHUTDOWN 2

workqueue_entry_t *threadpool_queue_work(threadpool_t *pool,
                                         int (*fn)(void *, void *),
                                         void (*reply_fn)(void *),
                                         void *arg);
int threadpool_queue_for_all(threadpool_t *pool,
                             void *(*dup_fn)(void *),
                             int (*fn)(void *, void *),
                             void (*reply_fn)(void *),
                             void *arg);
int workqueue_entry_cancel(workqueue_entry_t *pending_work);
threadpool_t *threadpool_new(int n_threads,
                             replyqueue_t *replyqueue,
                             void *(*new_thread_state_fn)(void*),
                             void (*free_thread_state_fn)(void*),
                             void *arg);
replyqueue_t *threadpool_get_replyqueue(threadpool_t *tp);

replyqueue_t *replyqueue_new(void);
tor_socket_t replyqueue_get_socket(replyqueue_t *rq);
void replyqueue_process(replyqueue_t *queue);

#endif
