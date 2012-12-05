/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file onion.c
 * \brief Functions to queue create cells, handle onionskin
 * parsing and creation, and wrap the various onionskin types.
 **/

#include "or.h"
#include "circuitlist.h"
#include "config.h"
#include "onion.h"
#include "onion_fast.h"
#include "onion_ntor.h"
#include "onion_tap.h"
#include "rephist.h"
#include "router.h"

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

/* XXXX Check lengths vs MAX_ONIONSKIN_{CHALLENGE,REPLY}_LEN */

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

/* ============================================================ */

/** Fill in a server_onion_keys_t object at <b>keys</b> with all of the keys
 * and other info we might need to do onion handshakes.  (We make a copy of
 * our keys for each cpuworker to avoid race conditions with the main thread,
 * and to avoid locking) */
void
setup_server_onion_keys(server_onion_keys_t *keys)
{
  memset(keys, 0, sizeof(server_onion_keys_t));
  memcpy(keys->my_identity, router_get_my_id_digest(), DIGEST_LEN);
  dup_onion_keys(&keys->onion_key, &keys->last_onion_key);
#ifdef CURVE25519_ENABLED
  keys->curve25519_key_map = construct_ntor_key_map();
#endif
}

/** Release all storage held in <b>keys</b>, but do not free <b>keys</b>
 * itself (as it's likely to be stack-allocated.) */
void
release_server_onion_keys(server_onion_keys_t *keys)
{
  if (! keys)
    return;

  crypto_pk_free(keys->onion_key);
  crypto_pk_free(keys->last_onion_key);
#ifdef CURVE25519_ENABLED
  ntor_key_map_free(keys->curve25519_key_map);
#endif
  memset(keys, 0, sizeof(server_onion_keys_t));
}

/** Release whatever storage is held in <b>state</b>, depending on its
 * type, and clear its pointer. */
void
onion_handshake_state_release(onion_handshake_state_t *state)
{
  switch (state->tag) {
  case ONION_HANDSHAKE_TYPE_TAP:
    crypto_dh_free(state->u.tap);
    state->u.tap = NULL;
    break;
  case ONION_HANDSHAKE_TYPE_FAST:
    fast_handshake_state_free(state->u.fast);
    state->u.fast = NULL;
    break;
#ifdef CURVE25519_ENABLED
  case ONION_HANDSHAKE_TYPE_NTOR:
    ntor_handshake_state_free(state->u.ntor);
    state->u.ntor = NULL;
    break;
#endif
  default:
    log_warn(LD_BUG, "called with unknown handshake state type %d",
             (int)state->tag);
    tor_fragile_assert();
  }
}

/** Perform the first step of a circuit-creation handshake of type <b>type</b>
 * (one of ONION_HANDSHAKE_TYPE_*): generate the initial "onion skin" in
 * <b>onion_skin_out</b>, and store any state information in <b>state_out</b>.
 * Return -1 on failure, and the length of the onionskin on acceptance.
 */
int
onion_skin_create(int type,
                  const extend_info_t *node,
                  onion_handshake_state_t *state_out,
                  uint8_t *onion_skin_out)
{
  int r = -1;

  switch (type) {
  case ONION_HANDSHAKE_TYPE_TAP:
    if (!node->onion_key)
      return -1;

    if (onion_skin_TAP_create(node->onion_key,
                              &state_out->u.tap,
                              (char*)onion_skin_out) < 0)
      return -1;

    r = TAP_ONIONSKIN_CHALLENGE_LEN;
    break;
  case ONION_HANDSHAKE_TYPE_FAST:
    if (fast_onionskin_create(&state_out->u.fast, onion_skin_out) < 0)
      return -1;

    r = CREATE_FAST_LEN;
    break;
  case ONION_HANDSHAKE_TYPE_NTOR:
#ifdef CURVE25519_ENABLED
    if (tor_mem_is_zero((const char*)node->curve25519_onion_key.public_key,
                        CURVE25519_PUBKEY_LEN))
      return -1;
    if (onion_skin_ntor_create((const uint8_t*)node->identity_digest,
                               &node->curve25519_onion_key,
                               &state_out->u.ntor,
                               onion_skin_out) < 0)
      return -1;

    r = NTOR_ONIONSKIN_LEN;
#else
    return -1;
#endif
    break;
  default:
    log_warn(LD_BUG, "called with unknown handshake state type %d", type);
    tor_fragile_assert();
    r = -1;
  }

  if (r > 0)
    state_out->tag = (uint16_t) type;

  return r;
}

/** Perform the second (server-side) step of a circuit-creation handshake of
 * type <b>type</b>, responding to the client request in <b>onion_skin</b>
 * using the keys in <b>keys</b>.  On success, write our response into
 * <b>reply_out</b>, generate <b>keys_out_len</b> bytes worth of key material
 * in <b>keys_out_len</b>, and return the length of the reply. On failure,
 * return -1.  */
int
onion_skin_server_handshake(int type,
                      const uint8_t *onion_skin,
                      const server_onion_keys_t *keys,
                      uint8_t *reply_out,
                      uint8_t *keys_out, size_t keys_out_len)
{
  int r = -1;

  switch (type) {
  case ONION_HANDSHAKE_TYPE_TAP:
    if (onion_skin_TAP_server_handshake((const char*)onion_skin,
                                        keys->onion_key, keys->last_onion_key,
                                        (char*)reply_out,
                                        (char*)keys_out, keys_out_len)<0)
      return -1;
    r = TAP_ONIONSKIN_REPLY_LEN;
    break;
  case ONION_HANDSHAKE_TYPE_FAST:
    if (fast_server_handshake(onion_skin, reply_out, keys_out, keys_out_len)<0)
      return -1;
    r = CREATED_FAST_LEN;
    break;
  case ONION_HANDSHAKE_TYPE_NTOR:
#ifdef CURVE25519_ENABLED
    if (onion_skin_ntor_server_handshake(onion_skin, keys->curve25519_key_map,
                                         keys->my_identity,
                                         reply_out, keys_out, keys_out_len)<0)
      return -1;
    r = NTOR_REPLY_LEN;
#else
    return -1;
#endif
    break;
  default:
    log_warn(LD_BUG, "called with unknown handshake state type %d", type);
    tor_fragile_assert();
    return -1;
  }

  /* XXXX we should generate the rendezvous nonce stuff too.  Some notes
   * below */
    // memcpy(hop->handshake_digest, reply+DH_KEY_LEN, DIGEST_LEN);

    //memcpy(hop->handshake_digest, reply+DIGEST_LEN, DIGEST_LEN);

  return r;
}

/** Perform the final (client-side) step of a circuit-creation handshake of
 * type <b>type</b>, using our state in <b>handshake_state</b> and the
 * server's response in <b>reply</b> On success, generate <b>keys_out_len</b>
 * bytes worth of key material in <b>keys_out_len</b>, set
 * <b>rend_authenticator_out</b> to the "KH" field that can be used to
 * establish introduction points at this hop, and return 0.  On failure,
 * return -1. */
int
onion_skin_client_handshake(int type,
                      const onion_handshake_state_t *handshake_state,
                      const uint8_t *reply,
                      uint8_t *keys_out, size_t keys_out_len,
                      uint8_t *rend_authenticator_out)
{
  if (handshake_state->tag != type)
    return -1;

  switch (type) {
  case ONION_HANDSHAKE_TYPE_TAP:
    if (onion_skin_TAP_client_handshake(handshake_state->u.tap,
                                        (const char*)reply,
                                        (char *)keys_out, keys_out_len) < 0)
      return -1;

    memcpy(rend_authenticator_out, reply+DH_KEY_LEN, DIGEST_LEN);

    return 0;
  case ONION_HANDSHAKE_TYPE_FAST:
    if (fast_client_handshake(handshake_state->u.fast, reply,
                              keys_out, keys_out_len) < 0)
      return -1;

    memcpy(rend_authenticator_out, reply+DIGEST_LEN, DIGEST_LEN);
    return 0;
#ifdef CURVE25519_ENABLED
  case ONION_HANDSHAKE_TYPE_NTOR:
    {
      size_t keys_tmp_len = keys_out_len + DIGEST_LEN;
      uint8_t *keys_tmp = tor_malloc(keys_tmp_len);
      if (onion_skin_ntor_client_handshake(handshake_state->u.ntor,
                                           reply,
                                           keys_tmp, keys_tmp_len) < 0) {
        tor_free(keys_tmp);
        return -1;
      }
      memcpy(keys_out, keys_tmp, keys_out_len);
      memcpy(rend_authenticator_out, keys_tmp + keys_out_len, DIGEST_LEN);
      memwipe(keys_tmp, 0, keys_tmp_len);
      tor_free(keys_tmp);
    }
    return 0;
#endif
  default:
    log_warn(LD_BUG, "called with unknown handshake state type %d", type);
    tor_fragile_assert();
    return -1;
  }
}

