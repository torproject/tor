/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "compat.h"
#include "compat_threads.h"
#include "util.h"
#include "workqueue.h"
#include "tor_queue.h"
#include "torlog.h"

#ifdef HAVE_UNISTD_H
// XXXX move wherever we move the write/send stuff
#include <unistd.h>
#endif

/*
  design:

  each thread has its own queue, try to keep at least elements min..max cycles
  worth of work on each queue.

keep array of threads; round-robin between them.

  When out of work, work-steal.

  alert threads with condition variables.

  alert main thread with fd, since it's libevent.


 */

typedef struct workqueue_entry_s {
  TOR_SIMPLEQ_ENTRY(workqueue_entry_s) next_work;
  int (*fn)(int status, void *state, void *arg);
  void (*reply_fn)(void *arg);
  void *arg;
} workqueue_entry_t;

struct replyqueue_s {
  tor_mutex_t lock;
  TOR_SIMPLEQ_HEAD(, workqueue_entry_s) answers;

  void (*alert_fn)(struct replyqueue_s *); // lock not held on this, next 2. 
  tor_socket_t write_sock;
  tor_socket_t read_sock;
};

typedef struct workerthread_s {
  tor_mutex_t lock;
  tor_cond_t condition;
  TOR_SIMPLEQ_HEAD(, workqueue_entry_s) work;
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
workqueue_entry_new(int (*fn)(int, void*, void*),
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
    while (!TOR_SIMPLEQ_EMPTY(&thread->work)) {
      /* lock held. */

      work = TOR_SIMPLEQ_FIRST(&thread->work);
      TOR_SIMPLEQ_REMOVE_HEAD(&thread->work, next_work);
      tor_mutex_release(&thread->lock);

      result = work->fn(WQ_CMD_RUN, thread->state, work->arg);

      if (result == WQ_RPL_QUEUE) {
        queue_reply(thread->reply_queue, work);
      } else {
        workqueue_entry_free(work);
      }

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
  was_empty = TOR_SIMPLEQ_EMPTY(&queue->answers);
  TOR_SIMPLEQ_INSERT_TAIL(&queue->answers, work, next_work);
  tor_mutex_release(&queue->lock);

  if (was_empty) {
    queue->alert_fn(queue);
  }
}


static void
alert_by_fd(replyqueue_t *queue)
{
  /* XXX extract this into new function */
#ifndef _WIN32
  (void) send(queue->write_sock, "x", 1, 0);
#else
  (void) write(queue->write_sock, "x", 1);
#endif
}

static workerthread_t *
workerthread_new(void *state, replyqueue_t *replyqueue)
{
  workerthread_t *thr = tor_malloc_zero(sizeof(workerthread_t));
  tor_mutex_init_for_cond(&thr->lock);
  tor_cond_init(&thr->condition);
  TOR_SIMPLEQ_INIT(&thr->work);
  thr->state = state;
  thr->reply_queue = replyqueue;

  if (spawn_func(worker_thread_main, thr) < 0) {
    log_err(LD_GENERAL, "Can't launch worker thread.");
    return NULL;
  }

  return thr;
}

void *
threadpool_queue_work(threadpool_t *pool,
                      int (*fn)(int, void *, void *),
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
  TOR_SIMPLEQ_INSERT_TAIL(&worker->work, ent, next_work);

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
  tor_socket_t pair[2];
  replyqueue_t *rq;
  int r;

  /* XXX extract this into new function */
#ifdef _WIN32
  r = tor_socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
#else
  r = pipe(pair);
#endif
  if (r < 0)
    return NULL;

  set_socket_nonblocking(pair[0]); /* the read-size should be nonblocking. */
#if defined(FD_CLOEXEC)
  fcntl(pair[0], F_SETFD, FD_CLOEXEC);
  fcntl(pair[1], F_SETFD, FD_CLOEXEC);
#endif

  rq = tor_malloc_zero(sizeof(replyqueue_t));

  tor_mutex_init(&rq->lock);
  TOR_SIMPLEQ_INIT(&rq->answers);

  rq->read_sock = pair[0];
  rq->write_sock = pair[1];
  rq->alert_fn = alert_by_fd;

  return rq;
}

tor_socket_t
replyqueue_get_socket(replyqueue_t *rq)
{
  return rq->read_sock;
}

void
replyqueue_process(replyqueue_t *queue)
{
  ssize_t r;

  /* XXX extract this into new function */
  do {
    char buf[64];
#ifdef _WIN32
    r = recv(queue->read_sock, buf, sizeof(buf), 0);
#else
    r = read(queue->read_sock, buf, sizeof(buf));
#endif
  } while (r > 0);

  /* XXXX freak out on r == 0, or r == "error, not retryable". */

  tor_mutex_acquire(&queue->lock);
  while (!TOR_SIMPLEQ_EMPTY(&queue->answers)) {
    /* lock held. */
    workqueue_entry_t *work = TOR_SIMPLEQ_FIRST(&queue->answers);
    TOR_SIMPLEQ_REMOVE_HEAD(&queue->answers, next_work);
    tor_mutex_release(&queue->lock);

    work->reply_fn(work->arg);
    workqueue_entry_free(work);

    tor_mutex_acquire(&queue->lock);
  }

  tor_mutex_release(&queue->lock);
}
