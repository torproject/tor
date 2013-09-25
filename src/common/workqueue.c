/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "compat.h"
#include "compat_threads.h"
#include "util.h"
#include "workqueue.h"
#include "tor_queue.h"
#include "torlog.h"

/*
  design:

  each thread has its own queue, try to keep at least elements min..max cycles
  worth of work on each queue.

keep array of threads; round-robin between them.

  When out of work, work-steal.

  alert threads with condition variables.

  alert main thread with fd, since it's libevent.


 */

struct workqueue_entry_s {
  TOR_TAILQ_ENTRY(workqueue_entry_s) next_work;
  struct workerthread_s *on_thread;
  uint8_t pending;
  int (*fn)(void *state, void *arg);
  void (*reply_fn)(void *arg);
  void *arg;
};

struct replyqueue_s {
  tor_mutex_t lock;
  TOR_TAILQ_HEAD(, workqueue_entry_s) answers;

  alert_sockets_t alert; // lock not held on this.
};

typedef struct workerthread_s {
  tor_mutex_t lock;
  tor_cond_t condition;
  TOR_TAILQ_HEAD(, workqueue_entry_s) work;
  unsigned is_running;
  unsigned is_shut_down;
  unsigned waiting;
  void *state;
  replyqueue_t *reply_queue;
} workerthread_t;

struct threadpool_s {
  workerthread_t **threads;
  int next_for_work;

  tor_mutex_t lock;
  int n_threads;

  replyqueue_t *reply_queue;

  void *(*new_thread_state_fn)(void*);
  void (*free_thread_state_fn)(void*);
  void *new_thread_state_arg;

};

static void queue_reply(replyqueue_t *queue, workqueue_entry_t *work);

static workqueue_entry_t *
workqueue_entry_new(int (*fn)(void*, void*),
                    void (*reply_fn)(void*),
                    void *arg)
{
  workqueue_entry_t *ent = tor_malloc_zero(sizeof(workqueue_entry_t));
  ent->fn = fn;
  ent->reply_fn = reply_fn;
  ent->arg = arg;
  return ent;
}

static void
workqueue_entry_free(workqueue_entry_t *ent)
{
  if (!ent)
    return;
  tor_free(ent);
}

int
workqueue_entry_cancel(workqueue_entry_t *ent)
{
  int cancelled = 0;
  tor_mutex_acquire(&ent->on_thread->lock);
  if (ent->pending) {
    TOR_TAILQ_REMOVE(&ent->on_thread->work, ent, next_work);
    cancelled = 1;
  }
  tor_mutex_release(&ent->on_thread->lock);

  if (cancelled) {
    tor_free(ent);
  }
  return cancelled;
}

static void
worker_thread_main(void *thread_)
{
  workerthread_t *thread = thread_;
  workqueue_entry_t *work;
  int result;

  tor_mutex_acquire(&thread->lock);

  thread->is_running = 1;
  while (1) {
    /* lock held. */
    while (!TOR_TAILQ_EMPTY(&thread->work)) {
      /* lock held. */

      work = TOR_TAILQ_FIRST(&thread->work);
      TOR_TAILQ_REMOVE(&thread->work, work, next_work);
      work->pending = 0;
      tor_mutex_release(&thread->lock);

      result = work->fn(thread->state, work->arg);

      queue_reply(thread->reply_queue, work);

      tor_mutex_acquire(&thread->lock);
      if (result >= WQ_RPL_ERROR) {
        thread->is_running = 0;
        thread->is_shut_down = 1;
        tor_mutex_release(&thread->lock);
        return;
      }
    }
    /* Lock held; no work in this thread's queue. */

    /* TODO: Try work-stealing. */

    /* TODO: support an idle-function */

    thread->waiting = 1;
    if (tor_cond_wait(&thread->condition, &thread->lock, NULL) < 0)
      /* ERR */
    thread->waiting = 0;
  }
}

static void
queue_reply(replyqueue_t *queue, workqueue_entry_t *work)
{
  int was_empty;
  tor_mutex_acquire(&queue->lock);
  was_empty = TOR_TAILQ_EMPTY(&queue->answers);
  TOR_TAILQ_INSERT_TAIL(&queue->answers, work, next_work);
  tor_mutex_release(&queue->lock);

  if (was_empty) {
    if (queue->alert.alert_fn(queue->alert.write_fd) < 0) {
      /* XXXX complain! */
    }
  }
}

static workerthread_t *
workerthread_new(void *state, replyqueue_t *replyqueue)
{
  workerthread_t *thr = tor_malloc_zero(sizeof(workerthread_t));
  tor_mutex_init_for_cond(&thr->lock);
  tor_cond_init(&thr->condition);
  TOR_TAILQ_INIT(&thr->work);
  thr->state = state;
  thr->reply_queue = replyqueue;

  if (spawn_func(worker_thread_main, thr) < 0) {
    log_err(LD_GENERAL, "Can't launch worker thread.");
    return NULL;
  }

  return thr;
}

workqueue_entry_t *
threadpool_queue_work(threadpool_t *pool,
                      int (*fn)(void *, void *),
                      void (*reply_fn)(void *),
                      void *arg)
{
  workqueue_entry_t *ent;
  workerthread_t *worker;

  tor_mutex_acquire(&pool->lock);
  worker = pool->threads[pool->next_for_work++];
  if (!worker) {
    tor_mutex_release(&pool->lock);
    return NULL;
  }
  if (pool->next_for_work >= pool->n_threads)
    pool->next_for_work = 0;
  tor_mutex_release(&pool->lock);

  ent = workqueue_entry_new(fn, reply_fn, arg);

  tor_mutex_acquire(&worker->lock);
  ent->on_thread = worker;
  ent->pending = 1;
  TOR_TAILQ_INSERT_TAIL(&worker->work, ent, next_work);

  if (worker->waiting) /* XXXX inside or outside of lock?? */
    tor_cond_signal_one(&worker->condition);

  tor_mutex_release(&worker->lock);

  return ent;
}

int
threadpool_start_threads(threadpool_t *pool, int n)
{
  tor_mutex_acquire(&pool->lock);

  if (pool->n_threads < n)
    pool->threads = tor_realloc(pool->threads, sizeof(workerthread_t*)*n);

  while (pool->n_threads < n) {
    void *state = pool->new_thread_state_fn(pool->new_thread_state_arg);
    workerthread_t *thr = workerthread_new(state, pool->reply_queue);

    if (!thr) {
      tor_mutex_release(&pool->lock);
      return -1;
    }
    pool->threads[pool->n_threads++] = thr;
  }
  tor_mutex_release(&pool->lock);

  return 0;
}

threadpool_t *
threadpool_new(int n_threads,
               replyqueue_t *replyqueue,
               void *(*new_thread_state_fn)(void*),
               void (*free_thread_state_fn)(void*),
               void *arg)
{
  threadpool_t *pool;
  pool = tor_malloc_zero(sizeof(threadpool_t));
  tor_mutex_init(&pool->lock);
  pool->new_thread_state_fn = new_thread_state_fn;
  pool->new_thread_state_arg = arg;
  pool->free_thread_state_fn = free_thread_state_fn;
  pool->reply_queue = replyqueue;

  if (threadpool_start_threads(pool, n_threads) < 0) {
    tor_mutex_uninit(&pool->lock);
    tor_free(pool);
    return NULL;
  }

  return pool;
}

replyqueue_t *
threadpool_get_replyqueue(threadpool_t *tp)
{
  return tp->reply_queue;
}

replyqueue_t *
replyqueue_new(void)
{
  replyqueue_t *rq;

  rq = tor_malloc_zero(sizeof(replyqueue_t));
  if (alert_sockets_create(&rq->alert) < 0) {
    tor_free(rq);
    return NULL;
  }

  tor_mutex_init(&rq->lock);
  TOR_TAILQ_INIT(&rq->answers);

  return rq;
}

tor_socket_t
replyqueue_get_socket(replyqueue_t *rq)
{
  return rq->alert.read_fd;
}

void
replyqueue_process(replyqueue_t *queue)
{
  if (queue->alert.drain_fn(queue->alert.read_fd) < 0) {
    /* XXXX complain! */
  }

  tor_mutex_acquire(&queue->lock);
  while (!TOR_TAILQ_EMPTY(&queue->answers)) {
    /* lock held. */
    workqueue_entry_t *work = TOR_TAILQ_FIRST(&queue->answers);
    TOR_TAILQ_REMOVE(&queue->answers, work, next_work);
    tor_mutex_release(&queue->lock);

    work->reply_fn(work->arg);
    workqueue_entry_free(work);

    tor_mutex_acquire(&queue->lock);
  }

  tor_mutex_release(&queue->lock);
}

