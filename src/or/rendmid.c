/* Copyright 2004 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/* Respond to an ESTABLISH_INTRO cell by setting the circuit's purpose and
 * rendevous service.
 */
int
rend_mid_establish_intro(circuit_t *circ, const char *request, int request_len)
{
  crypto_pk_env_t *pk = NULL;
  char buf[DIGEST_LEN+9];
  char expected_digest[DIGEST_LEN];
  char pk_digest[DIGEST_LEN];
  int asn1len;
  circuit_t *c;
  char hexid[9];

  log_fn(LOG_INFO,
         "Received an ESTABLISH_INTRO request on circuit %d", circ->p_circ_id);

  if (circ->purpose != CIRCUIT_PURPOSE_OR || circ->n_conn) {
    log_fn(LOG_WARN, "Rejecting ESTABLISH_INTRO on non-OR or non-edge circuit");
    goto err;
  }
  if (request_len < 2+DIGEST_LEN)
    goto truncated;
  /* First 2 bytes: length of asn1-encoded key. */
  asn1len = get_uint16(request);

  /* Next asn1len bytes: asn1-encoded key. */
  if (request_len < 2+DIGEST_LEN+asn1len)
    goto truncated;
  pk = crypto_pk_asn1_decode(request+2, asn1len);
  if (!pk) {
    log_fn(LOG_WARN, "Couldn't decode public key");
    goto err;
  }

  /* Next 20 bytes: Hash of handshake_digest | "INTRODUCE" */
  memcpy(buf, circ->handshake_digest, DIGEST_LEN);
  memcpy(buf+DIGEST_LEN, "INTRODUCE", 9);
  if (crypto_digest(buf, DIGEST_LEN+9, expected_digest)<0) {
    log_fn(LOG_WARN, "Error computing digest");
    goto err;
  }
  if (memcmp(expected_digest, request+2+asn1len, DIGEST_LEN)) {
    log_fn(LOG_WARN, "Hash of session info was not as expected");
    goto err;
  }
  /* Rest of body: signature of previous data */
  if (crypto_pk_public_checksig_digest(pk, request, 2+asn1len+DIGEST_LEN,
                                       request+2+DIGEST_LEN+asn1len,
                                       request_len-(2+DIGEST_LEN+asn1len))<0) {
    log_fn(LOG_WARN, "Incorrect signature on ESTABLISH_INTRO cell; rejecting");
    goto err;
  }

  /* The request is valid.  First, compute the hash of Bob's PK.*/
  if (crypto_pk_get_digest(pk, pk_digest)<0) {
    log_fn(LOG_WARN, "Couldn't hash public key.");
    goto err;
  }

  hex_encode(pk_digest, 4, hexid);

  /* Close any other intro circuits with the same pk. */
  c = NULL;
  while ((c = circuit_get_next_by_pk_and_purpose(
                                c,pk_digest,CIRCUIT_PURPOSE_INTRO_POINT))) {
    log_fn(LOG_INFO, "Replacing old circuit %d for service %s",
           c->p_circ_id, hexid);
    circuit_mark_for_close(c);
  }

  /* Acknlowedge the request. */
  if (connection_edge_send_command(NULL,circ,
                                   RELAY_COMMAND_INTRO_ESTABLISHED,
                                   "", 0, NULL)<0) {
    log_fn(LOG_WARN, "Couldn't send INTRO_ESTABLISHED cell");
    goto err;
  }

  /* Now, set up this circuit. */
  circ->purpose = CIRCUIT_PURPOSE_INTRO_POINT;
  memcpy(circ->rend_pk_digest, pk_digest, 20);

  log_fn(LOG_INFO,
         "Established introduction point on circuit %d for service %s",
         circ->p_circ_id, hexid);

  return 0;
 truncated:
  log_fn(LOG_WARN, "Rejecting truncated ESTABLISH_INTRO cell");
 err:
  if (pk) crypto_free_pk_env(pk);
  circuit_mark_for_close(circ);
  return -1;
}

/* Process an INTRODUCE1 cell by finding the corresponding introduction
 * circuit, and relaying the body of the INTRODUCE1 cell inside an
 * INTRODUCE2 cell.
 */
int
rend_mid_introduce(circuit_t *circ, const char *request, int request_len)
{
  circuit_t *intro_circ;
  char hexid[9];

  if (circ->purpose != CIRCUIT_PURPOSE_OR || circ->n_conn) {
    log_fn(LOG_WARN, "Rejecting INTRODUCE1 on non-OR or non-edge circuit %d",
           circ->p_circ_id);
    goto err;
  }

  if (request_len < 246) {
    log_fn(LOG_WARN,
           "Impossibly short INTRODUCE1 cell on circuit %d; dropping.",
           circ->p_circ_id);
    goto err;
  }

  hex_encode(request,4,hexid);

  /* The first 20 bytes are all we look at: they have a hash of Bob's PK. */
  intro_circ = circuit_get_next_by_pk_and_purpose(
                             NULL, request, CIRCUIT_PURPOSE_INTRO_POINT);
  if (!intro_circ) {
    log_fn(LOG_WARN,
           "No intro circ found for INTRODUCE1 cell (%s) from circuit %d; dropping",
           hexid, circ->p_circ_id);
    goto err;
  }

  log_fn(LOG_INFO,
         "Sending introduction request for service %s from circ %d to circ %d",
         hexid, circ->p_circ_id, intro_circ->p_circ_id);

  /* Great.  Now we just relay the cell down the circuit. */
  if (connection_edge_send_command(NULL, intro_circ,
                                   RELAY_COMMAND_INTRODUCE2,
                                   request, request_len, NULL)) {
    log_fn(LOG_WARN, "Unable to send INTRODUCE2 cell to OP.");
    goto err;
  }

  return 0;
 err:
  circuit_mark_for_close(circ); /* Is this right? */
  return -1;
}

/* Process an ESTABLISH_RENDEZVOUS cell by settingthe circuit's purpose and
 * rendezvous cookie.
 */
int
rend_mid_establish_rendezvous(circuit_t *circ, const char *request, int request_len)
{
  char hexid[9];

  if (circ->purpose != CIRCUIT_PURPOSE_OR || circ->n_conn) {
    log_fn(LOG_WARN, "Tried to establish rendezvous on non-OR or non-edge circuit");
    goto err;
  }

  if (request_len != REND_COOKIE_LEN) {
    log_fn(LOG_WARN, "Invalid length on ESTABLISH_RENDEZVOUS");
    goto err;
  }

  if (circuit_get_rendezvous(request)) {
    log_fn(LOG_WARN, "Duplicate rendezvous cookie in ESTABLISH_RENDEZVOUS");
    goto err;
  }

  /* Acknlowedge the request. */
  if (connection_edge_send_command(NULL,circ,
                                   RELAY_COMMAND_RENDEZVOUS_ESTABLISHED,
                                   "", 0, NULL)<0) {
    log_fn(LOG_WARN, "Couldn't send RENDEZVOUS_ESTABLISHED cell");
    goto err;
  }

  circ->purpose = CIRCUIT_PURPOSE_REND_POINT_WAITING;
  memcpy(circ->rend_cookie, request, REND_COOKIE_LEN);

  hex_encode(request,4,hexid);
  log_fn(LOG_INFO, "Established rendezvous point on circuit %d for cookie %s",
         circ->p_circ_id, hexid);

  return 0;
 err:
  circuit_mark_for_close(circ);
  return -1;
}

/* Process a RENDEZVOUS1 cell by looking up the correct rendezvous circuit by its
 * relaying the cell's body in a RENDEZVOUS2 cell, and connecting the two circuits.
 */
int
rend_mid_rendezvous(circuit_t *circ, const char *request, int request_len)
{
  circuit_t *rend_circ;
  char hexid[9];

  if (request_len>=4) {
    hex_encode(request,4,hexid);
    log_fn(LOG_INFO, "Got request for rendezvous from circuit %d to cookie %s",
           circ->p_circ_id, hexid);
  }

  if (circ->purpose != CIRCUIT_PURPOSE_OR || circ->n_conn) {
    log_fn(LOG_WARN,
           "Tried to complete rendezvous on non-OR or non-edge circuit %d",
           circ->p_circ_id);
    goto err;
  }

  if (request_len != REND_COOKIE_LEN+DH_KEY_LEN+DIGEST_LEN) {
    log_fn(LOG_WARN,
           "Rejecting RENDEZVOUS1 cell with bad length (%d) on circuit %d",
           request_len, circ->p_circ_id);
    goto err;
  }

  rend_circ = circuit_get_rendezvous(request);
  if (!rend_circ) {
    log_fn(LOG_WARN,
           "Rejecting RENDEZVOUS1 cell with unrecognized rendezvous cookie %s",
           hexid);
    goto err;
  }

  /* Send the RENDEZVOUS2 cell to Alice. */
  if (connection_edge_send_command(NULL, rend_circ,
                                   RELAY_COMMAND_RENDEZVOUS2,
                                   request+20, request_len-20, NULL)) {
    log_fn(LOG_WARN, "Unable to send RENDEZVOUS2 cell to OP on circuit %d",
           rend_circ->p_circ_id);
    goto err;
  }

  /* Join the circuits. */
  log_fn(LOG_INFO,
         "Completing rendezvous: circuit %d joins circuit %d (cookie %s)",
         circ->p_circ_id, rend_circ->p_circ_id, hexid);

  circ->purpose = CIRCUIT_PURPOSE_REND_ESTABLISHED;
  rend_circ->purpose = CIRCUIT_PURPOSE_REND_ESTABLISHED;
  memset(circ->rend_cookie, 0, 20);

  rend_circ->rend_splice = circ;
  circ->rend_splice = rend_circ;

  return 0;
 err:
  circuit_mark_for_close(circ);
  return -1;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
