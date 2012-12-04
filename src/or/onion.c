/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file onion.c
 * \brief Functions to queue create cells, and handle onionskin
 * parsing and creation.
 **/

#include "or.h"
#include "circuitlist.h"
#include "config.h"
#include "onion.h"
#include "rephist.h"

/** Type for a linked list of circuits that are waiting for a free CPU worker
 * to process a waiting onion handshake. */
typedef struct onion_queue_t {
  or_circuit_t *circ;
  char *onionskin;
  time_t when_added;
  struct onion_queue_t *next;
} onion_queue_t;

/** 5 seconds on the onion queue til we just send back a destroy */
#define ONIONQUEUE_WAIT_CUTOFF 5

/** First and last elements in the linked list of circuits waiting for CPU
 * workers, or NULL if the list is empty.
 * @{ */
static onion_queue_t *ol_list=NULL;
static onion_queue_t *ol_tail=NULL;
/**@}*/
/** Length of ol_list */
static int ol_length=0;

/** Add <b>circ</b> to the end of ol_list and return 0, except
 * if ol_list is too long, in which case do nothing and return -1.
 */
int
onion_pending_add(or_circuit_t *circ, char *onionskin)
{
  onion_queue_t *tmp;
  time_t now = time(NULL);

  tmp = tor_malloc_zero(sizeof(onion_queue_t));
  tmp->circ = circ;
  tmp->onionskin = onionskin;
  tmp->when_added = now;

  if (!ol_tail) {
    tor_assert(!ol_list);
    tor_assert(!ol_length);
    ol_list = tmp;
    ol_tail = tmp;
    ol_length++;
    return 0;
  }

  tor_assert(ol_list);
  tor_assert(!ol_tail->next);

  if (ol_length >= get_options()->MaxOnionsPending) {
#define WARN_TOO_MANY_CIRC_CREATIONS_INTERVAL (60)
    static ratelim_t last_warned =
      RATELIM_INIT(WARN_TOO_MANY_CIRC_CREATIONS_INTERVAL);
    char *m;
    if ((m = rate_limit_log(&last_warned, approx_time()))) {
      log_warn(LD_GENERAL,
               "Your computer is too slow to handle this many circuit "
               "creation requests! Please consider using the "
               "MaxAdvertisedBandwidth config option or choosing a more "
               "restricted exit policy.%s",m);
      tor_free(m);
    }
    tor_free(tmp);
    return -1;
  }

  ol_length++;
  ol_tail->next = tmp;
  ol_tail = tmp;
  while ((int)(now - ol_list->when_added) >= ONIONQUEUE_WAIT_CUTOFF) {
    /* cull elderly requests. */
    circ = ol_list->circ;
    onion_pending_remove(ol_list->circ);
    log_info(LD_CIRC,
             "Circuit create request is too old; canceling due to overload.");
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_RESOURCELIMIT);
  }
  return 0;
}

/** Remove the first item from ol_list and return it, or return
 * NULL if the list is empty.
 */
or_circuit_t *
onion_next_task(char **onionskin_out)
{
  or_circuit_t *circ;

  if (!ol_list)
    return NULL; /* no onions pending, we're done */

  tor_assert(ol_list->circ);
  tor_assert(ol_list->circ->p_chan); /* make sure it's still valid */
  tor_assert(ol_length > 0);
  circ = ol_list->circ;
  *onionskin_out = ol_list->onionskin;
  ol_list->onionskin = NULL; /* prevent free. */
  onion_pending_remove(ol_list->circ);
  return circ;
}

/** Go through ol_list, find the onion_queue_t element which points to
 * circ, remove and free that element. Leave circ itself alone.
 */
void
onion_pending_remove(or_circuit_t *circ)
{
  onion_queue_t *tmpo, *victim;

  if (!ol_list)
    return; /* nothing here. */

  /* first check to see if it's the first entry */
  tmpo = ol_list;
  if (tmpo->circ == circ) {
    /* it's the first one. remove it from the list. */
    ol_list = tmpo->next;
    if (!ol_list)
      ol_tail = NULL;
    ol_length--;
    victim = tmpo;
  } else { /* we need to hunt through the rest of the list */
    for ( ;tmpo->next && tmpo->next->circ != circ; tmpo=tmpo->next) ;
    if (!tmpo->next) {
      log_debug(LD_GENERAL,
                "circ (p_circ_id %d) not in list, probably at cpuworker.",
                circ->p_circ_id);
      return;
    }
    /* now we know tmpo->next->circ == circ */
    victim = tmpo->next;
    tmpo->next = victim->next;
    if (ol_tail == victim)
      ol_tail = tmpo;
    ol_length--;
  }

  /* now victim points to the element that needs to be removed */

  tor_free(victim->onionskin);
  tor_free(victim);
}

/** Remove all circuits from the pending list.  Called from tor_free_all. */
void
clear_pending_onions(void)
{
  while (ol_list) {
    onion_queue_t *victim = ol_list;
    ol_list = victim->next;
    tor_free(victim->onionskin);
    tor_free(victim);
  }
  ol_list = ol_tail = NULL;
  ol_length = 0;
}

