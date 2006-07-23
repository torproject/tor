/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char onion_c_id[] =
  "$Id$";

/**
 * \file onion.c
 * \brief Functions to queue create cells, and handle onionskin
 * parsing and creation.
 **/

#include "or.h"

/** Type for a linked list of circuits that are waiting for a free CPU worker
 * to process a waiting onion handshake. */
typedef struct onion_queue_t {
  or_circuit_t *circ;
  time_t when_added;
  struct onion_queue_t *next;
} onion_queue_t;

/** 5 seconds on the onion queue til we just send back a destroy */
#define ONIONQUEUE_WAIT_CUTOFF 5

/** Global (within this file) variables used by the next few functions */
static onion_queue_t *ol_list=NULL;
static onion_queue_t *ol_tail=NULL;
/** Length of ol_list */
static int ol_length=0;

/** Add <b>circ</b> to the end of ol_list and return 0, except
 * if ol_list is too long, in which case do nothing and return -1.
 */
int
onion_pending_add(or_circuit_t *circ)
{
  onion_queue_t *tmp;
  time_t now = time(NULL);

  tmp = tor_malloc_zero(sizeof(onion_queue_t));
  tmp->circ = circ;
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
    log_warn(LD_GENERAL,
             "Your computer is too slow to handle this many circuit "
             "creation requests! Please consider using the "
             "MaxAdvertisedBandwidth config option or choosing a more "
             "restricted exit policy.");
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
             "Circuit create request is too old; cancelling due to overload.");
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_RESOURCELIMIT);
  }
  return 0;
}

/** Remove the first item from ol_list and return it, or return
 * NULL if the list is empty.
 */
or_circuit_t *
onion_next_task(void)
{
  or_circuit_t *circ;

  if (!ol_list)
    return NULL; /* no onions pending, we're done */

  tor_assert(ol_list->circ);
  tor_assert(ol_list->circ->p_conn); /* make sure it's still valid */
  tor_assert(ol_length > 0);
  circ = ol_list->circ;
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

  tor_free(victim);
}

/*----------------------------------------------------------------------*/

/** Given a router's 128 byte public key,
 * stores the following in onion_skin_out:
 *   - [42 bytes] OAEP padding
 *   - [16 bytes] Symmetric key for encrypting blob past RSA
 *   - [70 bytes] g^x part 1 (inside the RSA)
 *   - [58 bytes] g^x part 2 (symmetrically encrypted)
 *
 * Stores the DH private key into handshake_state_out for later completion
 * of the handshake.
 *
 * The meeting point/cookies and auth are zeroed out for now.
 */
int
onion_skin_create(crypto_pk_env_t *dest_router_key,
                  crypto_dh_env_t **handshake_state_out,
                  char *onion_skin_out) /* ONIONSKIN_CHALLENGE_LEN bytes */
{
  char *challenge = NULL;
  crypto_dh_env_t *dh = NULL;
  int dhbytes, pkbytes;

  tor_assert(dest_router_key);
  tor_assert(handshake_state_out);
  tor_assert(onion_skin_out);
  *handshake_state_out = NULL;
  memset(onion_skin_out, 0, ONIONSKIN_CHALLENGE_LEN);

  if (!(dh = crypto_dh_new()))
    goto err;

  dhbytes = crypto_dh_get_bytes(dh);
  pkbytes = crypto_pk_keysize(dest_router_key);
  tor_assert(dhbytes == 128);
  tor_assert(pkbytes == 128);
  challenge = tor_malloc_zero(DH_KEY_LEN);

  if (crypto_dh_get_public(dh, challenge, dhbytes))
    goto err;

#ifdef DEBUG_ONION_SKINS
#define PA(a,n) \
  { int _i; for (_i = 0; _i<n; ++_i) printf("%02x ",((int)(a)[_i])&0xFF); }

  printf("Client: client g^x:");
  PA(challenge+16,3);
  printf("...");
  PA(challenge+141,3);
  puts("");

  printf("Client: client symkey:");
  PA(challenge+0,16);
  puts("");
#endif

  /* set meeting point, meeting cookie, etc here. Leave zero for now. */
  if (crypto_pk_public_hybrid_encrypt(dest_router_key, onion_skin_out,
                                      challenge, DH_KEY_LEN,
                                      PK_PKCS1_OAEP_PADDING, 1)<0)
    goto err;

  tor_free(challenge);
  *handshake_state_out = dh;

  return 0;
 err:
  tor_free(challenge);
  if (dh) crypto_dh_free(dh);
  return -1;
}

/** Given an encrypted DH public key as generated by onion_skin_create,
 * and the private key for this onion router, generate the reply (128-byte
 * DH plus the first 20 bytes of shared key material), and store the
 * next key_out_len bytes of key material in key_out.
 */
int
onion_skin_server_handshake(const char *onion_skin, /*ONIONSKIN_CHALLENGE_LEN*/
                            crypto_pk_env_t *private_key,
                            crypto_pk_env_t *prev_private_key,
                            char *handshake_reply_out, /*ONIONSKIN_REPLY_LEN*/
                            char *key_out,
                            size_t key_out_len)
{
  char challenge[ONIONSKIN_CHALLENGE_LEN];
  crypto_dh_env_t *dh = NULL;
  int len;
  char *key_material=NULL;
  int i;
  crypto_pk_env_t *k;

  len = -1;
  for (i=0;i<2;++i) {
    k = i==0?private_key:prev_private_key;
    if (!k)
      break;
    len = crypto_pk_private_hybrid_decrypt(k, challenge,
                                           onion_skin, ONIONSKIN_CHALLENGE_LEN,
                                           PK_PKCS1_OAEP_PADDING,0);
    if (len>0)
      break;
  }
  if (len<0) {
    log_info(LD_PROTOCOL,
             "Couldn't decrypt onionskin: client may be using old onion key");
    goto err;
  } else if (len != DH_KEY_LEN) {
    log_warn(LD_PROTOCOL, "Unexpected onionskin length after decryption: %d",
             len);
    goto err;
  }

  dh = crypto_dh_new();
  if (crypto_dh_get_public(dh, handshake_reply_out, DH_KEY_LEN)) {
    log_info(LD_GENERAL, "crypto_dh_get_public failed.");
    goto err;
  }

#ifdef DEBUG_ONION_SKINS
  printf("Server: server g^y:");
  PA(handshake_reply_out+0,3);
  printf("...");
  PA(handshake_reply_out+125,3);
  puts("");
#endif

  key_material = tor_malloc(DIGEST_LEN+key_out_len);
  len = crypto_dh_compute_secret(dh, challenge, DH_KEY_LEN,
                                 key_material, DIGEST_LEN+key_out_len);
  if (len < 0) {
    log_info(LD_GENERAL, "crypto_dh_compute_secret failed.");
    goto err;
  }

  /* send back H(K|0) as proof that we learned K. */
  memcpy(handshake_reply_out+DH_KEY_LEN, key_material, DIGEST_LEN);

  /* use the rest of the key material for our shared keys, digests, etc */
  memcpy(key_out, key_material+DIGEST_LEN, key_out_len);

#ifdef DEBUG_ONION_SKINS
  printf("Server: key material:");
  PA(key_material, DH_KEY_LEN);
  puts("");
  printf("Server: keys out:");
  PA(key_out, key_out_len);
  puts("");
#endif

  tor_free(key_material);
  crypto_dh_free(dh);
  return 0;
 err:
  tor_free(key_material);
  if (dh) crypto_dh_free(dh);

  return -1;
}

/** Finish the client side of the DH handshake.
 * Given the 128 byte DH reply + 20 byte hash as generated by
 * onion_skin_server_handshake and the handshake state generated by
 * onion_skin_create, verify H(K) with the first 20 bytes of shared
 * key material, then generate key_out_len more bytes of shared key
 * material and store them in key_out.
 *
 * After the invocation, call crypto_dh_free on handshake_state.
 */
int
onion_skin_client_handshake(crypto_dh_env_t *handshake_state,
            const char *handshake_reply, /* ONIONSKIN_REPLY_LEN bytes */
            char *key_out,
            size_t key_out_len)
{
  int len;
  char *key_material=NULL;
  tor_assert(crypto_dh_get_bytes(handshake_state) == DH_KEY_LEN);

#ifdef DEBUG_ONION_SKINS
  printf("Client: server g^y:");
  PA(handshake_reply+0,3);
  printf("...");
  PA(handshake_reply+125,3);
  puts("");
#endif

  key_material = tor_malloc(20+key_out_len);
  len = crypto_dh_compute_secret(handshake_state, handshake_reply, DH_KEY_LEN,
                                 key_material, 20+key_out_len);
  if (len < 0)
    return -1;

  if (memcmp(key_material, handshake_reply+DH_KEY_LEN, 20)) {
    /* H(K) does *not* match. Something fishy. */
    tor_free(key_material);
    log_warn(LD_PROTOCOL,"Digest DOES NOT MATCH on onion handshake. "
             "Bug or attack.");
    return -1;
  }

  /* use the rest of the key material for our shared keys, digests, etc */
  memcpy(key_out, key_material+20, key_out_len);

#ifdef DEBUG_ONION_SKINS
  printf("Client: keys out:");
  PA(key_out, key_out_len);
  puts("");
#endif

  tor_free(key_material);
  return 0;
}

/** Implement the server side of the CREATE_FAST abbreviated handshake.  The
 * client has provided DIGEST_LEN key bytes in <b>key_in</b> ("x").  We
 * generate a reply of DIGEST_LEN*2 bytes in <b>key_out/b>, consisting of a
 * new random "y", followed by H(x|y) to check for correctness.  We set
 * <b>key_out_len</b> bytes of key material in <b>key_out</b>.
 * Return 0 on success, <0 on failure.
 **/
int
fast_server_handshake(const char *key_in, /* DIGEST_LEN bytes */
                      char *handshake_reply_out, /* DIGEST_LEN*2 bytes */
                      char *key_out,
                      size_t key_out_len)
{
  char tmp[DIGEST_LEN+DIGEST_LEN];
  char *out;
  size_t out_len;

  if (crypto_rand(handshake_reply_out, DIGEST_LEN)<0)
    return -1;

  memcpy(tmp, key_in, DIGEST_LEN);
  memcpy(tmp+DIGEST_LEN, handshake_reply_out, DIGEST_LEN);
  out_len = key_out_len+DIGEST_LEN;
  out = tor_malloc(out_len);
  if (crypto_expand_key_material(tmp, sizeof(tmp), out, out_len)) {
    tor_free(out);
    return -1;
  }
  memcpy(handshake_reply_out+DIGEST_LEN, out, DIGEST_LEN);
  memcpy(key_out, out+DIGEST_LEN, key_out_len);
  memset(tmp, 0, sizeof(tmp));
  memset(out, 0, out_len);
  tor_free(out);
  return 0;
}

/** Implement the second half of the client side of the CREATE_FAST handshake.
 * We sent the server <b>handshake_state</b> ("x") already, and the server
 * told us <b>handshake_reply_out</b> (y|H(x|y)).  Make sure that the hash is
 * correct, and generate key material in <b>key_out</b>.  Return 0 on success,
 * true on failure.
 *
 * NOTE: The "CREATE_FAST" handshake path is distinguishable from regular
 * "onionskin" handshakes, and is not secure if an adversary can see or modify
 * the messages.  Therefore, it should only be used by clients, and only as
 * the first hop of a circuit (since the first hop is already authenticated
 * and protected by TLS).
 */
int
fast_client_handshake(const char *handshake_state, /* DIGEST_LEN bytes */
                      const char *handshake_reply_out, /* DIGEST_LEN*2 bytes */
                      char *key_out,
                      size_t key_out_len)
{
  char tmp[DIGEST_LEN+DIGEST_LEN];
  char *out;
  size_t out_len;

  memcpy(tmp, handshake_state, DIGEST_LEN);
  memcpy(tmp+DIGEST_LEN, handshake_reply_out, DIGEST_LEN);
  out_len = key_out_len+DIGEST_LEN;
  out = tor_malloc(out_len);
  if (crypto_expand_key_material(tmp, sizeof(tmp), out, out_len)) {
    tor_free(out);
    return -1;
  }
  if (memcmp(out, handshake_reply_out+DIGEST_LEN, DIGEST_LEN)) {
    /* H(K) does *not* match. Something fishy. */
    log_warn(LD_PROTOCOL,"Digest DOES NOT MATCH on fast handshake. "
             "Bug or attack.");
    return -1;
  }
  memcpy(key_out, out+DIGEST_LEN, key_out_len);
  memset(tmp, 0, sizeof(tmp));
  memset(out, 0, out_len);
  tor_free(out);
  return 0;
}

/** Remove all circuits from the pending list.  Called from tor_free_all. */
void
clear_pending_onions(void)
{
  while (ol_list) {
    onion_queue_t *victim = ol_list;
    ol_list = victim->next;
    tor_free(victim);
  }
  ol_list = ol_tail = NULL;
  ol_length = 0;
}

