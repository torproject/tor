/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_circuitmap.c
 *
 * \brief Manage the hidden service circuitmap: A hash table that maps binary
 *  tokens to introduction and rendezvous circuits.
 **/

#define HS_CIRCUITMAP_PRIVATE

#include "or.h"
#include "config.h"
#include "circuitlist.h"
#include "hs_circuitmap.h"

/************************** HS circuitmap code *******************************/

/* This is the hidden service circuitmap. It's a hash table that maps
   introduction and rendezvous tokens to specific circuits such that given a
   token it's easy to find the corresponding circuit. */
static struct hs_circuitmap_ht *the_hs_circuitmap = NULL;

/* This is a helper function used by the hash table code (HT_). It returns 1 if
 * two circuits have the same HS token. */
static int
hs_circuits_have_same_token(const or_circuit_t *first_circuit,
                            const or_circuit_t *second_circuit)
{
  const hs_token_t *first_token;
  const hs_token_t *second_token;

  tor_assert(first_circuit);
  tor_assert(second_circuit);

  first_token = first_circuit->hs_token;
  second_token = second_circuit->hs_token;

  /* Both circs must have a token */
  if (BUG(!first_token) || BUG(!second_token)) {
    return 0;
  }

  if (first_token->type != second_token->type) {
    return 0;
  }

  if (first_token->token_len != second_token->token_len)
    return 0;

  return tor_memeq(first_token->token,
                   second_token->token,
                   first_token->token_len);
}

/* This is a helper function for the hash table code (HT_). It hashes a circuit
 * HS token into an unsigned int for use as a key by the hash table routines.*/
static inline unsigned int
hs_circuit_hash_token(const or_circuit_t *circuit)
{
  tor_assert(circuit->hs_token);

  return (unsigned) siphash24g(circuit->hs_token->token,
                               circuit->hs_token->token_len);
}

/* Register the circuitmap hash table */
HT_PROTOTYPE(hs_circuitmap_ht, // The name of the hashtable struct
             or_circuit_t,    // The name of the element struct,
             hs_circuitmap_node,        // The name of HT_ENTRY member
             hs_circuit_hash_token, hs_circuits_have_same_token)

HT_GENERATE2(hs_circuitmap_ht, or_circuit_t, hs_circuitmap_node,
             hs_circuit_hash_token, hs_circuits_have_same_token,
             0.6, tor_reallocarray, tor_free_)

#ifdef TOR_UNIT_TESTS

/* Return the global HS circuitmap. Used by unittests. */
hs_circuitmap_ht *
get_hs_circuitmap(void)
{
  return the_hs_circuitmap;
}

#endif

/****************** HS circuitmap utility functions **************************/

/** Return a new HS token of type <b>type</b> containing <b>token</b>. */
static hs_token_t *
hs_token_new(hs_token_type_t type, size_t token_len,
             const uint8_t *token)
{
  tor_assert(token);

  hs_token_t *hs_token = tor_malloc_zero(sizeof(hs_token_t));
  hs_token->type = type;
  hs_token->token_len = token_len;
  hs_token->token = tor_memdup(token, token_len);

  return hs_token;
}

/** Free memory allocated by this <b>hs_token</b>. */
static void
hs_token_free(hs_token_t *hs_token)
{
  if (!hs_token) {
    return;
  }

  tor_free(hs_token->token);
  tor_free(hs_token);
}

/** Return the circuit from the circuitmap with token <b>search_token</b>. */
static or_circuit_t *
get_circuit_with_token(hs_token_t *search_token)
{
  tor_assert(the_hs_circuitmap);

  /* We use a dummy circuit object for the hash table search routine. */
  or_circuit_t search_circ;
  search_circ.hs_token = search_token;
  return HT_FIND(hs_circuitmap_ht, the_hs_circuitmap, &search_circ);
}

/* Helper function that registers <b>circ</b> with <b>token</b> on the HS
   circuitmap. This function steals reference of <b>token</b>. */
static void
hs_circuitmap_register_impl(or_circuit_t *circ, hs_token_t *token)
{
  tor_assert(circ);
  tor_assert(token);
  tor_assert(the_hs_circuitmap);

  /* If this circuit already has a token, clear it. */
  if (circ->hs_token) {
    hs_circuitmap_remove_circuit(circ);
  }

  /* Kill old circuits with the same token. We want new intro/rend circuits to
     take precedence over old ones, so that HSes and clients and reestablish
     killed circuits without changing the HS token. */
  {
    or_circuit_t *found_circ;
    found_circ = get_circuit_with_token(token);
    if (found_circ) {
      hs_circuitmap_remove_circuit(found_circ);
      if (!found_circ->base_.marked_for_close) {
        circuit_mark_for_close(TO_CIRCUIT(found_circ),
                               END_CIRC_REASON_FINISHED);
      }
    }
  }

  /* Register circuit and token to circuitmap. */
  circ->hs_token = token;
  HT_INSERT(hs_circuitmap_ht, the_hs_circuitmap, circ);
}

/** Helper function: Register <b>circ</b> of <b>type</b> on the HS
 *  circuitmap. Use the HS <b>token</b> as the key to the hash table.  If
 *  <b>token</b> is not set, clear the circuit of any HS tokens. */
static void
hs_circuitmap_register_circuit(or_circuit_t *circ,
                               hs_token_type_t type, size_t token_len,
                               const uint8_t *token)
{
  hs_token_t *hs_token = NULL;

  /* Create a new token and register it to the circuitmap */
  tor_assert(token);
  hs_token = hs_token_new(type, token_len, token);
  tor_assert(hs_token);
  hs_circuitmap_register_impl(circ, hs_token);
}

/* Query circuitmap for circuit with <b>token</b> of size <b>token_len</b>.
 * Only returns a circuit with purpose equal to the <b>wanted_circ_purpose</b>
 * parameter and if it is NOT marked for close. Return NULL if no such circuit
 * is found. */
static or_circuit_t *
hs_circuitmap_get_circuit(hs_token_type_t type,
                          size_t token_len,
                          const uint8_t *token,
                          uint8_t wanted_circ_purpose)
{
  or_circuit_t *found_circ = NULL;

  tor_assert(the_hs_circuitmap);

  /* Check the circuitmap if we have a circuit with this token */
  {
    hs_token_t *search_hs_token = hs_token_new(type, token_len, token);
    tor_assert(search_hs_token);
    found_circ = get_circuit_with_token(search_hs_token);
    hs_token_free(search_hs_token);
  }

  /* Check that the circuit is useful to us */
  if (!found_circ ||
      found_circ->base_.purpose != wanted_circ_purpose ||
      found_circ->base_.marked_for_close) {
    return NULL;
  }

  return found_circ;
}

/************** Public circuitmap API ****************************************/

/* Public function: Return v3 introduction circuit with <b>auth_key</b>. Return
 * NULL if no such circuit is found in the circuitmap. */
or_circuit_t *
hs_circuitmap_get_intro_circ_v3(const ed25519_public_key_t *auth_key)
{
  tor_assert(auth_key);

  return hs_circuitmap_get_circuit(HS_TOKEN_INTRO_V3,
                                   ED25519_PUBKEY_LEN, auth_key->pubkey,
                                   CIRCUIT_PURPOSE_INTRO_POINT);
}

/* Public function: Return v2 introduction circuit with <b>digest</b>. Return
 * NULL if no such circuit is found in the circuitmap. */
or_circuit_t *
hs_circuitmap_get_intro_circ_v2(const uint8_t *digest)
{
  tor_assert(digest);

  return hs_circuitmap_get_circuit(HS_TOKEN_INTRO_V2,
                                   REND_TOKEN_LEN, digest,
                                   CIRCUIT_PURPOSE_INTRO_POINT);
}

/* Public function: Return rendezvous circuit with rendezvous
 * <b>cookie</b>. Return NULL if no such circuit is found in the circuitmap. */
or_circuit_t *
hs_circuitmap_get_rend_circ(const uint8_t *cookie)
{
  tor_assert(cookie);

  return hs_circuitmap_get_circuit(HS_TOKEN_REND,
                                   REND_TOKEN_LEN, cookie,
                                   CIRCUIT_PURPOSE_REND_POINT_WAITING);
}

/* Public function: Register rendezvous circuit with key <b>cookie</b> to the
 * circuitmap. */
void
hs_circuitmap_register_rend_circ(or_circuit_t *circ, const uint8_t *cookie)
{
  hs_circuitmap_register_circuit(circ,
                                 HS_TOKEN_REND,
                                 REND_TOKEN_LEN, cookie);
}

/* Public function: Register v2 intro circuit with key <b>digest</b> to the
 * circuitmap. */
void
hs_circuitmap_register_intro_circ_v2(or_circuit_t *circ, const uint8_t *digest)
{
  hs_circuitmap_register_circuit(circ,
                                 HS_TOKEN_INTRO_V2,
                                 REND_TOKEN_LEN, digest);
}

/* Public function: Register v3 intro circuit with key <b>auth_key</b> to the
 * circuitmap. */
void
hs_circuitmap_register_intro_circ_v3(or_circuit_t *circ,
                                     const ed25519_public_key_t *auth_key)
{
  hs_circuitmap_register_circuit(circ,
                                 HS_TOKEN_INTRO_V3,
                                 ED25519_PUBKEY_LEN, auth_key->pubkey);
}

/** Remove this circuit from the HS circuitmap. Clear its HS token, and remove
 *  it from the hashtable. */
void
hs_circuitmap_remove_circuit(or_circuit_t *circ)
{
  tor_assert(the_hs_circuitmap);

  if (!circ || !circ->hs_token) {
    return;
  }

  /* Remove circ from circuitmap */
  or_circuit_t *tmp;
  tmp = HT_REMOVE(hs_circuitmap_ht, the_hs_circuitmap, circ);
  /* ... and ensure the removal was successful. */
  if (tmp) {
    tor_assert(tmp == circ);
  } else {
    log_warn(LD_BUG, "Could not find circuit (%u) in circuitmap.",
             circ->p_circ_id);
  }

  /* Clear token from circ */
  hs_token_free(circ->hs_token);
  circ->hs_token = NULL;
}

/* Initialize the global HS circuitmap. */
void
hs_circuitmap_init(void)
{
  tor_assert(!the_hs_circuitmap);

  the_hs_circuitmap = tor_malloc_zero(sizeof(struct hs_circuitmap_ht));
  HT_INIT(hs_circuitmap_ht, the_hs_circuitmap);
}

/* Free all memory allocated by the global HS circuitmap. */
void
hs_circuitmap_free_all(void)
{
  if (the_hs_circuitmap) {
    HT_CLEAR(hs_circuitmap_ht, the_hs_circuitmap);
    tor_free(the_hs_circuitmap);
  }
}

