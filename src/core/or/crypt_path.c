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
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"

#include "core/or/crypt_path_st.h"
#include "core/or/cell_st.h"

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
  crypt_path_t *hop = tor_malloc_zero(sizeof(crypt_path_t));

  /* link hop into the cpath, at the end. */
  onion_append_to_cpath(head_ptr, hop);

  hop->magic = CRYPT_PATH_MAGIC;
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
