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

static int opt_verbose = 0;
static int opt_n_threads = 8;
static int opt_n_items = 10000;
static int opt_n_inflight = 1000;
static int opt_n_lowwater = 250;
static int opt_ratio_rsa = 5;

#ifdef TRACK_RESPONSES
tor_mutex_t bitmap_mutex;
int handled_len;
bitarray_t *handled;
#endif

typedef struct state_s {
  int magic;
  int n_handled;
  crypto_pk_t *rsa;
  curve25519_secret_key_t ecdh;
  int is_shutdown;
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
workqueue_do_rsa(void *state, void *work)
{
  rsa_work_t *rw = work;
  state_t *st = state;
  crypto_pk_t *rsa = st->rsa;
  uint8_t sig[256];
  int len;

  tor_assert(st->magic == 13371337);

  len = crypto_pk_private_sign(rsa, (char*)sig, 256,
                               (char*)rw->msg, rw->msglen);
  if (len < 0) {
    rw->msglen = 0;
    return WQ_RPL_ERROR;
  }

  memset(rw->msg, 0, sizeof(rw->msg));
  rw->msglen = len;
  memcpy(rw->msg, sig, len);
  ++st->n_handled;

  mark_handled(rw->serial);

  return WQ_RPL_REPLY;
}

static int
workqueue_do_shutdown(void *state, void *work)
{
  (void)state;
  (void)work;
  crypto_pk_free(((state_t*)state)->rsa);
  tor_free(state);
  return WQ_RPL_SHUTDOWN;
}

static int
workqueue_do_ecdh(void *state, void *work)
{
  ecdh_work_t *ew = work;
  uint8_t output[CURVE25519_OUTPUT_LEN];
  state_t *st = state;

  tor_assert(st->magic == 13371337);

  curve25519_handshake(output, &st->ecdh, &ew->u.pk);
  memcpy(ew->u.msg, output, CURVE25519_OUTPUT_LEN);
  ++st->n_handled;
  mark_handled(ew->serial);
  return WQ_RPL_REPLY;
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
  int add_rsa =
    opt_ratio_rsa == 0 ||
    tor_weak_random_range(&weak_rng, opt_ratio_rsa) == 0;
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

static int shutting_down = 0;
static int n_shutdowns_done = 0;

static void
shutdown_reply(void *arg)
{
  (void)arg;
  tor_assert(shutting_down);
  ++n_shutdowns_done;
  if (n_shutdowns_done == opt_n_threads) {
    tor_event_base_loopexit(tor_libevent_get_base(), NULL);
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

  if (opt_verbose)
    printf("%d / %d\n", n_received, n_sent);
#ifdef TRACK_RESPONSES
  tor_mutex_acquire(&bitmap_mutex);
  for (i = 0; i < opt_n_items; ++i) {
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

  if (n_sent - n_received < opt_n_lowwater) {
    while (n_sent < n_received + opt_n_inflight && n_sent < opt_n_items) {
      if (! add_work(tp)) {
        puts("Couldn't add work.");
        tor_event_base_loopexit(tor_libevent_get_base(), NULL);
      }
    }
  }

  if (shutting_down == 0 && n_received == n_sent && n_sent >= opt_n_items) {
    shutting_down = 1;
    threadpool_queue_for_all(tp, NULL, workqueue_do_shutdown, shutdown_reply, NULL);
  }
}

static void
help(void)
{
  puts(
     "Options:\n"
     "    -N <items>    Run this many items of work\n"
     "    -T <threads>  Use this many threads\n"
     "    -I <inflight> Have no more than this many requests queued at once\n"
     "    -L <lowwater> Add items whenever fewer than this many are pending\n"
     "    -R <ratio>    Make one out of this many items be a slow (RSA) one\n"
     "    --no-{eventfd2,eventfd,pipe2,pipe,socketpair}\n"
     "                  Disable one of the alert_socket backends.");
}

int
main(int argc, char **argv)
{
  replyqueue_t *rq;
  threadpool_t *tp;
  int i;
  tor_libevent_cfg evcfg;
  struct event *ev;
  uint32_t as_flags = 0;

  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "-v")) {
      opt_verbose = 1;
    } else if (!strcmp(argv[i], "-T") && i+1<argc) {
      opt_n_threads = atoi(argv[++i]);
    } else if (!strcmp(argv[i], "-N") && i+1<argc) {
      opt_n_items = atoi(argv[++i]);
    } else if (!strcmp(argv[i], "-I") && i+1<argc) {
      opt_n_inflight = atoi(argv[++i]);
    } else if (!strcmp(argv[i], "-L") && i+1<argc) {
      opt_n_lowwater = atoi(argv[++i]);
    } else if (!strcmp(argv[i], "-R") && i+1<argc) {
      opt_ratio_rsa = atoi(argv[++i]);
    } else if (!strcmp(argv[i], "--no-eventfd2")) {
      as_flags |= ASOCKS_NOEVENTFD2;
    } else if (!strcmp(argv[i], "--no-eventfd")) {
      as_flags |= ASOCKS_NOEVENTFD;
    } else if (!strcmp(argv[i], "--no-pipe2")) {
      as_flags |= ASOCKS_NOPIPE2;
    } else if (!strcmp(argv[i], "--no-pipe")) {
      as_flags |= ASOCKS_NOPIPE;
    } else if (!strcmp(argv[i], "--no-socketpair")) {
      as_flags |= ASOCKS_NOSOCKETPAIR;
    } else if (!strcmp(argv[i], "-h")) {
      help();
      return 0;
    } else {
      help();
      return 1;
    }
  }
  if (opt_n_threads < 1 ||
      opt_n_items < 1 || opt_n_inflight < 1 || opt_n_lowwater < 0 ||
      opt_ratio_rsa < 0) {
    help();
    return 1;
  }

  init_logging(1);
  crypto_global_init(1, NULL, NULL);
  crypto_seed_rng(1);

  rq = replyqueue_new(as_flags);
  tor_assert(rq);
  tp = threadpool_new(opt_n_threads,
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
  handled = bitarray_init_zero(opt_n_items);
  received = bitarray_init_zero(opt_n_items);
  tor_mutex_init(&bitmap_mutex);
  handled_len = opt_n_items;
#endif

  for (i = 0; i < opt_n_inflight; ++i) {
    if (! add_work(tp)) {
      puts("Couldn't add work.");
      return 1;
    }
  }

  {
    struct timeval limit = { 30, 0 };
    tor_event_base_loopexit(tor_libevent_get_base(), &limit);
  }

  event_base_loop(tor_libevent_get_base(), 0);

  if (n_sent != opt_n_items || n_received != n_sent ||
      n_shutdowns_done != opt_n_threads) {
    puts("FAIL");
    return 1;
  } else {
    puts("OK");
    return 0;
  }
}
