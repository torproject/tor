/*
 * Copyright (c) 2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypt_path.c
 *
 * \brief Functions dealing with layered circuit encryption. This file aims to
 *   provide an API around the crypt_path_t structure which holds crypto
 *   information about a specific hop of a circuit.
 **/

#define CRYPT_PATH_PRIVATE

#include "core/or/or.h"
#include "core/or/crypt_path.h"

#include "core/crypto/relay_crypto.h"
#include "core/crypto/onion_crypto.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"

#include "lib/crypt_ops/crypto_dh.h"
#include "lib/crypt_ops/crypto_util.h"

#include "core/or/crypt_path_st.h"
#include "core/or/cell_st.h"

/** Initialize and return a minimal crypt_path_t */
crypt_path_t *
crypt_path_new(void)
{
  crypt_path_t *cpath = tor_malloc_zero(sizeof(crypt_path_t));
  cpath->magic = CRYPT_PATH_MAGIC;
  cpath->private = tor_malloc_zero(sizeof(struct crypt_path_private_t));

  return cpath;
}

/** Add <b>new_hop</b> to the end of the doubly-linked-list <b>head_ptr</b>.
 * This function is used to extend cpath by another hop.
 */
void
onion_append_to_cpath(crypt_path_t **head_ptr, crypt_path_t *new_hop)
{
  if (*head_ptr) {
    new_hop->next = (*head_ptr);
    new_hop->prev = (*head_ptr)->prev;
    (*head_ptr)->prev->next = new_hop;
    (*head_ptr)->prev = new_hop;
  } else {
    *head_ptr = new_hop;
    new_hop->prev = new_hop->next = new_hop;
  }
}

/** Create a new hop, annotate it with information about its
 * corresponding router <b>choice</b>, and append it to the
 * end of the cpath <b>head_ptr</b>. */
int
onion_append_hop(crypt_path_t **head_ptr, extend_info_t *choice)
{
  crypt_path_t *hop = crypt_path_new();

  /* link hop into the cpath, at the end. */
  onion_append_to_cpath(head_ptr, hop);

  hop->state = CPATH_STATE_CLOSED;

  hop->extend_info = extend_info_dup(choice);

  hop->package_window = circuit_initial_package_window();
  hop->deliver_window = CIRCWINDOW_START;

  return 0;
}

/** Verify that cpath <b>cp</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
void
assert_cpath_ok(const crypt_path_t *cp)
{
  const crypt_path_t *start = cp;

  do {
    assert_cpath_layer_ok(cp);
    /* layers must be in sequence of: "open* awaiting? closed*" */
    if (cp != start) {
      if (cp->state == CPATH_STATE_AWAITING_KEYS) {
        tor_assert(cp->prev->state == CPATH_STATE_OPEN);
      } else if (cp->state == CPATH_STATE_OPEN) {
        tor_assert(cp->prev->state == CPATH_STATE_OPEN);
      }
    }
    cp = cp->next;
    tor_assert(cp);
  } while (cp != start);
}

/** Verify that cpath layer <b>cp</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
void
assert_cpath_layer_ok(const crypt_path_t *cp)
{
//  tor_assert(cp->addr); /* these are zero for rendezvous extra-hops */
//  tor_assert(cp->port);
  tor_assert(cp);
  tor_assert(cp->magic == CRYPT_PATH_MAGIC);
  switch (cp->state)
    {
    case CPATH_STATE_OPEN:
      relay_crypto_assert_ok(&cp->private->crypto);
      /* fall through */
    case CPATH_STATE_CLOSED:
      /*XXXX Assert that there's no handshake_state either. */
      tor_assert(!cp->rend_dh_handshake_state);
      break;
    case CPATH_STATE_AWAITING_KEYS:
      /* tor_assert(cp->dh_handshake_state); */
      break;
    default:
      log_fn(LOG_ERR, LD_BUG, "Unexpected state %d", cp->state);
      tor_assert(0);
    }
  tor_assert(cp->package_window >= 0);
  tor_assert(cp->deliver_window >= 0);
}

/** Initialize cpath-\>{f|b}_{crypto|digest} from the key material in key_data.
 *
 * If <b>is_hs_v3</b> is set, this cpath will be used for next gen hidden
 * service circuits and <b>key_data</b> must be at least
 * HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN bytes in length.
 *
 * If <b>is_hs_v3</b> is not set, key_data must contain CPATH_KEY_MATERIAL_LEN
 * bytes, which are used as follows:
 *   - 20 to initialize f_digest
 *   - 20 to initialize b_digest
 *   - 16 to key f_crypto
 *   - 16 to key b_crypto
 *
 * (If 'reverse' is true, then f_XX and b_XX are swapped.)
 *
 * Return 0 if init was successful, else -1 if it failed.
 */
int
circuit_init_cpath_crypto(crypt_path_t *cpath,
                          const char *key_data, size_t key_data_len,
                          int reverse, int is_hs_v3)
{

  tor_assert(cpath);
  return relay_crypto_init(&cpath->private->crypto, key_data, key_data_len,
                           reverse, is_hs_v3);
}

/** Deallocate space associated with the cpath node <b>victim</b>. */
void
circuit_free_cpath_node(crypt_path_t *victim)
{
  if (!victim)
    return;

  relay_crypto_clear(&victim->private->crypto);
  onion_handshake_state_release(&victim->handshake_state);
  crypto_dh_free(victim->rend_dh_handshake_state);
  extend_info_free(victim->extend_info);
  tor_free(victim->private);

  memwipe(victim, 0xBB, sizeof(crypt_path_t)); /* poison memory */
  tor_free(victim);
}

/********************** cpath crypto API *******************************/

/** Encrypt or decrypt <b>payload</b> using the crypto of <b>cpath</b>. Actual
 *  operation decided by <b>is_decrypt</b>.  */
void
cpath_crypt_cell(const crypt_path_t *cpath, uint8_t *payload, bool is_decrypt)
{
  if (is_decrypt) {
    relay_crypt_one_payload(cpath->private->crypto.b_crypto, payload);
  } else {
    relay_crypt_one_payload(cpath->private->crypto.f_crypto, payload);
  }
}

/** Getter for the incoming digest of <b>cpath</b>. */
struct crypto_digest_t *
cpath_get_incoming_digest(const crypt_path_t *cpath)
{
  return cpath->private->crypto.b_digest;
}

/** Set the right integrity digest on the outgoing <b>cell</b> based on the
 *  cell payload and update the forward digest of <b>cpath</b>. */
void
cpath_set_cell_forward_digest(crypt_path_t *cpath, cell_t *cell)
{
  relay_set_digest(cpath->private->crypto.f_digest, cell);
}
