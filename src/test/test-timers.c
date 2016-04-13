/* Copyright 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_EVENT2_EVENT_H
#include <event2/event.h>
#else
#include <event.h>
#endif

#include "compat.h"
#include "compat_libevent.h"
#include "crypto.h"
#include "timers.h"
#include "util.h"

#define N_TIMERS 1000
#define MAX_DURATION 30

static struct timeval fire_at[N_TIMERS] = {{0,0}};
static int fired[N_TIMERS] = {0};
static struct timeval difference[N_TIMERS] = {{0,0}};
static tor_timer_t *timers[N_TIMERS] = {NULL};

static int n_fired = 0;

static void
timer_cb(tor_timer_t *t, void *arg, const struct timeval *now)
{
  tor_timer_t **t_ptr = arg;
  tor_assert(*t_ptr == t);
  int idx = (int) (t_ptr - timers);
  ++fired[idx];
  timersub(now, &fire_at[idx], &difference[idx]);
  ++n_fired;
  // printf("%d / %d\n",n_fired, N_TIMERS);
  if (n_fired == N_TIMERS) {
    event_base_loopbreak(tor_libevent_get_base());
  }
}

int
main(int argc, char **argv)
{
  (void)argc;
  (void)argv;
  tor_libevent_cfg cfg;
  memset(&cfg, 0, sizeof(cfg));
  tor_libevent_initialize(&cfg);
  timers_initialize();

  int i;
  struct timeval now;
  tor_gettimeofday(&now);
  for (i = 0; i < N_TIMERS; ++i) {
    struct timeval delay;
    delay.tv_sec = crypto_rand_int_range(0,MAX_DURATION);
    delay.tv_usec = crypto_rand_int_range(0,1000000);
    timeradd(&now, &delay, &fire_at[i]);
    timers[i] = timer_new(timer_cb, &timers[i], 0);
    timer_schedule(timers[i], &delay);
  }

  event_base_loop(tor_libevent_get_base(), 0);

  uint64_t total_difference = 0;
  uint64_t total_square_difference = 0;
  tor_assert(n_fired == N_TIMERS);
  for (i = 0; i < N_TIMERS; ++i) {
    tor_assert(fired[i] == 1);
    uint64_t diff = difference[i].tv_usec + difference[i].tv_sec * 1000000;
    total_difference += diff;
    total_square_difference += diff*diff;
  }
  const uint64_t mean_diff = total_difference / N_TIMERS;
  printf("mean difference: "U64_FORMAT" usec\n",
         U64_PRINTF_ARG(mean_diff));

  const double mean_sq = ((double)total_square_difference) / N_TIMERS;
  const double sq_mean = mean_diff * mean_diff;
  const double stddev = sqrt(mean_sq - sq_mean);
  printf("standard deviation: %lf usec\n", stddev);

  if (mean_diff > 500*1000 || stddev > 500*1000) {
    printf("Either your system is under ridiculous load, or the "
           "timer backend is broken.\n");
    return 1;
  } else if (mean_diff > 2000 || stddev > 2000) {
    printf("Either your system is a bit slow or the "
           "timer backend is odd.\n");
    return 0;
  } else {
    printf("Looks good enough.\n");
  }
  return 0;
}
