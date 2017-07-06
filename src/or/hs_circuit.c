/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_circuit.c
 **/

#include "or.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"

#include "hs_circuit.h"
#include "hs_ident.h"
#include "hs_ntor.h"

/* A circuit is about to become an e2e rendezvous circuit. Check
 * <b>circ_purpose</b> and ensure that it's properly set. Return true iff
 * circuit purpose is properly set, otherwise return false. */
static int
circuit_purpose_is_correct_for_rend(unsigned int circ_purpose, int is_service_side)
{
  if (is_service_side) {
    if (circ_purpose != CIRCUIT_PURPOSE_S_CONNECT_REND) {
      log_fn(LOG_PROTOCOL_WARN, LD_GENERAL,
             "HS e2e circuit setup with wrong purpose(%d)", circ_purpose);
      return 0;
    }
  }

  if (!is_service_side) {
    if (circ_purpose != CIRCUIT_PURPOSE_C_REND_READY &&
        circ_purpose != CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED) {
      log_fn(LOG_PROTOCOL_WARN, LD_GENERAL,
             "Client e2e circuit setup with wrong purpose(%d)", circ_purpose);
      return 0;
    }
  }

  return 1;
}

/* Create and return a crypt path for the final hop of a v3 prop224 rendezvous
 * circuit. Initialize the crypt path crypto using the output material from the
 * ntor key exchange at <b>ntor_key_seed</b>.
 *
 * If <b>is_service_side</b> is set, we are the hidden service and the final
 * hop of the rendezvous circuit is the client on the other side. */
static crypt_path_t *
create_rend_cpath(const uint8_t *ntor_key_seed, int is_service_side)
{
  uint8_t keys[HS_NTOR_KEY_EXPANSION_KDF_OUT_LEN];
  crypt_path_t *cpath = NULL;

  /* Do the key expansion */
  hs_ntor_circuit_key_expansion(ntor_key_seed, keys);

  /* Setup the cpath */
  cpath = tor_malloc_zero(sizeof(crypt_path_t));
  cpath->magic = CRYPT_PATH_MAGIC;

  if (circuit_init_cpath_crypto(cpath, (char*)keys, sizeof(keys),
                                is_service_side, 1) < 0) {
    tor_free(cpath);
    goto err;
  }

 err:
  memwipe(keys, 0, sizeof(keys));
  return cpath;
}

/* We are a v2 legacy HS client: Create and return a crypt path for the hidden
 * service on the other side of the rendezvous circuit <b>circ</b>. Initialize
 * the crypt path crypto using the body of the RENDEZVOUS1 cell at
 * <b>rend_cell_body</b> (which must be at least DH_KEY_LEN+DIGEST_LEN bytes).
 */
static crypt_path_t *
create_rend_cpath_legacy(origin_circuit_t *circ, const uint8_t *rend_cell_body)
{
  crypt_path_t *hop = NULL;
  char keys[DIGEST_LEN+CPATH_KEY_MATERIAL_LEN];

  /* first DH_KEY_LEN bytes are g^y from the service. Finish the dh
   * handshake...*/
  tor_assert(circ->build_state);
  tor_assert(circ->build_state->pending_final_cpath);
  hop = circ->build_state->pending_final_cpath;

  tor_assert(hop->rend_dh_handshake_state);
  if (crypto_dh_compute_secret(LOG_PROTOCOL_WARN, hop->rend_dh_handshake_state,
                               (char*)rend_cell_body, DH_KEY_LEN,
                               keys, DIGEST_LEN+CPATH_KEY_MATERIAL_LEN)<0) {
    log_warn(LD_GENERAL, "Couldn't complete DH handshake.");
    goto err;
  }
  /* ... and set up cpath. */
  if (circuit_init_cpath_crypto(hop,
                                keys+DIGEST_LEN, sizeof(keys)-DIGEST_LEN,
                                0, 0) < 0)
    goto err;

  /* Check whether the digest is right... */
  if (tor_memneq(keys, rend_cell_body+DH_KEY_LEN, DIGEST_LEN)) {
    log_warn(LD_PROTOCOL, "Incorrect digest of key material.");
    goto err;
  }

  /* clean up the crypto stuff we just made */
  crypto_dh_free(hop->rend_dh_handshake_state);
  hop->rend_dh_handshake_state = NULL;

  goto done;

 err:
  hop = NULL;

 done:
  memwipe(keys, 0, sizeof(keys));
  return hop;
}

/* Append the final <b>hop</b> to the cpath of the rend <b>circ</b>, and mark
 * <b>circ</b> ready for use to transfer HS relay cells. */
static void
finalize_rend_circuit(origin_circuit_t *circ, crypt_path_t *hop,
                      int is_service_side)
{
  tor_assert(circ);
  tor_assert(hop);

  /* Notify the circuit state machine that we are splicing this circuit */
  int new_circ_purpose = is_service_side ?
    CIRCUIT_PURPOSE_S_REND_JOINED : CIRCUIT_PURPOSE_C_REND_JOINED;
  circuit_change_purpose(TO_CIRCUIT(circ), new_circ_purpose);

  /* All is well. Extend the circuit. */
  hop->state = CPATH_STATE_OPEN;
  /* Set the windows to default. */
  hop->package_window = circuit_initial_package_window();
  hop->deliver_window = CIRCWINDOW_START;

  /* Now that this circuit has finished connecting to its destination,
   * make sure circuit_get_open_circ_or_launch is willing to return it
   * so we can actually use it. */
  circ->hs_circ_has_timed_out = 0;

  /* Append the hop to the cpath of this circuit */
  onion_append_to_cpath(&circ->cpath, hop);

  /* In legacy code, 'pending_final_cpath' points to the final hop we just
   * appended to the cpath. We set the original pointer to NULL so that we
   * don't double free it. */
  if (circ->build_state) {
    circ->build_state->pending_final_cpath = NULL;
  }

  /* Finally, mark circuit as ready to be used for client streams */
  if (!is_service_side) {
    circuit_try_attaching_streams(circ);
  }
}

/* Circuit <b>circ</b> just finished the rend ntor key exchange. Use the key
 * exchange output material at <b>ntor_key_seed</b> and setup <b>circ</b> to
 * serve as a rendezvous end-to-end circuit between the client and the
 * service. If <b>is_service_side</b> is set, then we are the hidden service
 * and the other side is the client.
 *
 * Return 0 if the operation went well; in case of error return -1. */
int
hs_circuit_setup_e2e_rend_circ(origin_circuit_t *circ,
                               const uint8_t *ntor_key_seed,
                               int is_service_side)
{
  if (BUG(!circuit_purpose_is_correct_for_rend(TO_CIRCUIT(circ)->purpose,
                                        is_service_side))) {
    return -1;
  }

  crypt_path_t *hop = create_rend_cpath(ntor_key_seed, is_service_side);
  if (!hop) {
    log_warn(LD_REND, "Couldn't get v3 %s cpath!",
             is_service_side ? "service-side" : "client-side");
    return -1;
  }

  finalize_rend_circuit(circ, hop, is_service_side);

  return 0;
}

/* We are a v2 legacy HS client and we just received a RENDEZVOUS1 cell
 * <b>rend_cell_body</b> on <b>circ</b>. Finish up the DH key exchange and then
 * extend the crypt path of <b>circ</b> so that the hidden service is on the
 * other side. */
int
hs_circuit_setup_e2e_rend_circ_legacy_client(origin_circuit_t *circ,
                                             const uint8_t *rend_cell_body)
{

  if (BUG(!circuit_purpose_is_correct_for_rend(
                                      TO_CIRCUIT(circ)->purpose, 0))) {
    return -1;
  }

  crypt_path_t *hop = create_rend_cpath_legacy(circ, rend_cell_body);
  if (!hop) {
    log_warn(LD_GENERAL, "Couldn't get v2 cpath.");
    return -1;
  }

  finalize_rend_circuit(circ, hop, 0);

  return 0;
}

