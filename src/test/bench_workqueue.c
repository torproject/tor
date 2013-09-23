/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "compat_threads.h"
#include "onion.h"
#include "workqueue.h"
#include "crypto.h"
#include "crypto_curve25519.h"
#include "compat_libevent.h"

#include <stdio.h>
#ifdef HAVE_EVENT2_EVENT_H
#include <event2/event.h>
#else
#include <event.h>
#endif

#ifdef TRACK_RESPONSES
tor_mutex_t bitmap_mutex;
int handled_len;
bitarray_t *handled;
#endif

#define N_ITEMS 10000
#define N_INFLIGHT 1000
#define RELAUNCH_AT 250

typedef struct state_s {
  int magic;
  int n_handled;
  crypto_pk_t *rsa;
  curve25519_secret_key_t ecdh;
} state_t;

typedef struct rsa_work_s {
  int serial;
  uint8_t msg[128];
  uint8_t msglen;
} rsa_work_t;

typedef struct ecdh_work_s {
  int serial;
  union {
    curve25519_public_key_t pk;
    uint8_t msg[32];
  } u;
} ecdh_work_t;

static void
mark_handled(int serial)
{
#ifdef TRACK_RESPONSES
  tor_mutex_acquire(&bitmap_mutex);
  tor_assert(serial < handled_len);
  tor_assert(! bitarray_is_set(handled, serial));
  bitarray_set(handled, serial);
  tor_mutex_release(&bitmap_mutex);
#else
  (void)serial;
#endif
}

static int
workqueue_do_rsa(int cmd, void *state, void *work)
{
  rsa_work_t *rw = work;
  state_t *st = state;
  crypto_pk_t *rsa = st->rsa;
  uint8_t sig[256];
  int len;

  tor_assert(st->magic == 13371337);

  if (cmd == WQ_CMD_CANCEL) {
    tor_free(work);
    return WQ_RPL_NOQUEUE;
  }

  len = crypto_pk_private_sign(rsa, (char*)sig, 256,
                               (char*)rw->msg, rw->msglen);
  if (len < 0) {
    tor_free(work);
    return WQ_RPL_NOQUEUE;
  }

  memset(rw->msg, 0, sizeof(rw->msg));
  rw->msglen = len;
  memcpy(rw->msg, sig, len);
  ++st->n_handled;

  mark_handled(rw->serial);

  return WQ_RPL_QUEUE;
}

#if 0
static int
workqueue_do_shutdown(int cmd, void *state, void *work)
{
  (void)state;
  (void)work;
  (void)cmd;
  crypto_pk_free(((state_t*)state)->rsa);
  tor_free(state);
  return WQ_RPL_SHUTDOWN;
}
#endif

static int
workqueue_do_ecdh(int cmd, void *state, void *work)
{
  ecdh_work_t *ew = work;
  uint8_t output[CURVE25519_OUTPUT_LEN];
  state_t *st = state;

  tor_assert(st->magic == 13371337);

  if (cmd == WQ_CMD_CANCEL) {
    tor_free(work);
    return WQ_RPL_NOQUEUE;
  }

  curve25519_handshake(output, &st->ecdh, &ew->u.pk);
  memcpy(ew->u.msg, output, CURVE25519_OUTPUT_LEN);
  ++st->n_handled;
  mark_handled(ew->serial);
  return WQ_RPL_QUEUE;
}

static void *
new_state(void *arg)
{
  state_t *st;
  (void)arg;

  st = tor_malloc(sizeof(*st));
  /* Every thread gets its own keys. not a problem for benchmarking */
  st->rsa = crypto_pk_new();
  if (crypto_pk_generate_key_with_bits(st->rsa, 1024) < 0) {
    puts("keygen failed");
    crypto_pk_free(st->rsa);
    tor_free(st);
    return NULL;
  }
  curve25519_secret_key_generate(&st->ecdh, 0);
  st->magic = 13371337;
  return st;
}

static void
free_state(void *arg)
{
  state_t *st = arg;
  crypto_pk_free(st->rsa);
  tor_free(st);
}

static tor_weak_rng_t weak_rng;
static int n_sent = 0;
static int rsa_sent = 0;
static int ecdh_sent = 0;
static int n_received = 0;

#ifdef TRACK_RESPONSES
bitarray_t *received;
#endif

static void
handle_reply(void *arg)
{
#ifdef TRACK_RESPONSES
  rsa_work_t *rw = arg; /* Naughty cast, but only looking at serial. */
  tor_assert(! bitarray_is_set(received, rw->serial));
  bitarray_set(received,rw->serial);
#endif

  tor_free(arg);
  ++n_received;
}

static int
add_work(threadpool_t *tp)
{
  int add_rsa = tor_weak_random_range(&weak_rng, 5) == 0;
  if (add_rsa) {
    rsa_work_t *w = tor_malloc_zero(sizeof(*w));
    w->serial = n_sent++;
    crypto_rand((char*)w->msg, 20);
    w->msglen = 20;
    ++rsa_sent;
    return threadpool_queue_work(tp, workqueue_do_rsa, handle_reply, w) != NULL;
  } else {
    ecdh_work_t *w = tor_malloc_zero(sizeof(*w));
    w->serial = n_sent++;
    /* Not strictly right, but this is just for benchmarks. */
    crypto_rand((char*)w->u.pk.public_key, 32);
    ++ecdh_sent;
    return threadpool_queue_work(tp, workqueue_do_ecdh, handle_reply, w) != NULL;
  }
}

static void
replysock_readable_cb(tor_socket_t sock, short what, void *arg)
{
  threadpool_t *tp = arg;
  replyqueue_t *rq = threadpool_get_replyqueue(tp);

  int old_r = n_received;
  (void) sock;
  (void) what;

  replyqueue_process(rq);
  if (old_r == n_received)
    return;

  printf("%d / %d\n", n_received, n_sent);
#ifdef TRACK_RESPONSES
  tor_mutex_acquire(&bitmap_mutex);
  for (i = 0; i < N_ITEMS; ++i) {
    if (bitarray_is_set(received, i))
      putc('o', stdout);
    else if (bitarray_is_set(handled, i))
      putc('!', stdout);
    else
      putc('.', stdout);
  }
  puts("");
  tor_mutex_release(&bitmap_mutex);
#endif

  if (n_sent - n_received < RELAUNCH_AT) {
    while (n_sent < n_received + N_INFLIGHT && n_sent < N_ITEMS) {
      if (! add_work(tp)) {
        puts("Couldn't add work.");
        tor_event_base_loopexit(tor_libevent_get_base(), NULL);
      }
    }
  }

  if (n_received == n_sent && n_sent >= N_ITEMS) {
    tor_event_base_loopexit(tor_libevent_get_base(), NULL);
  }
}

int
main(int argc, char **argv)
{
  replyqueue_t *rq;
  threadpool_t *tp;
  int i;
  tor_libevent_cfg evcfg;
  struct event *ev;

  (void)argc;
  (void)argv;

  init_logging(1);
  crypto_global_init(1, NULL, NULL);
  crypto_seed_rng(1);

  rq = replyqueue_new();
  tor_assert(rq);
  tp = threadpool_new(16,
                      rq, new_state, free_state, NULL);
  tor_assert(tp);

  crypto_seed_weak_rng(&weak_rng);

  memset(&evcfg, 0, sizeof(evcfg));
  tor_libevent_initialize(&evcfg);

  ev = tor_event_new(tor_libevent_get_base(),
                     replyqueue_get_socket(rq), EV_READ|EV_PERSIST,
                     replysock_readable_cb, tp);

  event_add(ev, NULL);

#ifdef TRACK_RESPONSES
  handled = bitarray_init_zero(N_ITEMS);
  received = bitarray_init_zero(N_ITEMS);
  tor_mutex_init(&bitmap_mutex);
  handled_len = N_ITEMS;
#endif

  for (i = 0; i < N_INFLIGHT; ++i) {
    if (! add_work(tp)) {
      puts("Couldn't add work.");
      return 1;
    }
  }

  event_base_loop(tor_libevent_get_base(), 0);

  return 0;
}
