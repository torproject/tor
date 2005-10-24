/* Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char rendmid_c_id[] = "$Id$";

/**
 * \file rendmid.c
 * \brief Implement introductions points and rendezvous points.
 **/

#define NEW_LOG_INTERFACE
#include "or.h"

/** Respond to an ESTABLISH_INTRO cell by checking the signed data and
 * setting the circuit's purpose and service pk digest.
 */
int
rend_mid_establish_intro(circuit_t *circ, const char *request, size_t request_len)
{
  crypto_pk_env_t *pk = NULL;
  char buf[DIGEST_LEN+9];
  char expected_digest[DIGEST_LEN];
  char pk_digest[DIGEST_LEN];
  size_t asn1len;
  circuit_t *c;
  char serviceid[REND_SERVICE_ID_LEN+1];

  info(LD_REND,
       "Received an ESTABLISH_INTRO request on circuit %d", circ->p_circ_id);

  if (circ->purpose != CIRCUIT_PURPOSE_OR || circ->n_conn) {
    warn(LD_PROTOCOL, "Rejecting ESTABLISH_INTRO on non-OR or non-edge circuit.");
    goto err;
  }
  if (request_len < 2+DIGEST_LEN)
    goto truncated;
  /* First 2 bytes: length of asn1-encoded key. */
  asn1len = ntohs(get_uint16(request));

  /* Next asn1len bytes: asn1-encoded key. */
  if (request_len < 2+DIGEST_LEN+asn1len)
    goto truncated;
  pk = crypto_pk_asn1_decode(request+2, asn1len);
  if (!pk) {
    warn(LD_PROTOCOL, "Couldn't decode public key.");
    goto err;
  }

  /* Next 20 bytes: Hash of handshake_digest | "INTRODUCE" */
  memcpy(buf, circ->handshake_digest, DIGEST_LEN);
  memcpy(buf+DIGEST_LEN, "INTRODUCE", 9);
  if (crypto_digest(expected_digest, buf, DIGEST_LEN+9) < 0) {
    warn(LD_BUG, "Internal error computing digest.");
    goto err;
  }
  if (memcmp(expected_digest, request+2+asn1len, DIGEST_LEN)) {
    warn(LD_PROTOCOL, "Hash of session info was not as expected.");
    goto err;
  }
  /* Rest of body: signature of previous data */
  if (crypto_pk_public_checksig_digest(pk, request, 2+asn1len+DIGEST_LEN,
                                       request+2+DIGEST_LEN+asn1len,
                                       request_len-(2+DIGEST_LEN+asn1len))<0) {
    warn(LD_PROTOCOL, "Incorrect signature on ESTABLISH_INTRO cell; rejecting.");
    goto err;
  }

  /* The request is valid.  First, compute the hash of Bob's PK.*/
  if (crypto_pk_get_digest(pk, pk_digest)<0) {
    warn(LD_BUG, "Internal error: couldn't hash public key.");
    goto err;
  }

  crypto_free_pk_env(pk); /* don't need it anymore */
  pk = NULL; /* so we don't free it again if err */

  base32_encode(serviceid, REND_SERVICE_ID_LEN+1, pk_digest,10);

  /* Close any other intro circuits with the same pk. */
  c = NULL;
  while ((c = circuit_get_next_by_pk_and_purpose(
                                c,pk_digest,CIRCUIT_PURPOSE_INTRO_POINT))) {
    info(LD_REND, "Replacing old circuit %d for service %s",
           c->p_circ_id, safe_str(serviceid));
    circuit_mark_for_close(c);
  }

  /* Acknowledge the request. */
  if (connection_edge_send_command(NULL,circ,
                                   RELAY_COMMAND_INTRO_ESTABLISHED,
                                   "", 0, NULL)<0) {
    info(LD_GENERAL, "Couldn't send INTRO_ESTABLISHED cell.");
    goto err;
  }

  /* Now, set up this circuit. */
  circ->purpose = CIRCUIT_PURPOSE_INTRO_POINT;
  memcpy(circ->rend_pk_digest, pk_digest, DIGEST_LEN);

  info(LD_REND,
       "Established introduction point on circuit %d for service %s",
       circ->p_circ_id, safe_str(serviceid));

  return 0;
 truncated:
  warn(LD_PROTOCOL, "Rejecting truncated ESTABLISH_INTRO cell.");
 err:
  if (pk) crypto_free_pk_env(pk);
  circuit_mark_for_close(circ);
  return -1;
}

/** Process an INTRODUCE1 cell by finding the corresponding introduction
 * circuit, and relaying the body of the INTRODUCE1 cell inside an
 * INTRODUCE2 cell.
 */
int
rend_mid_introduce(circuit_t *circ, const char *request, size_t request_len)
{
  circuit_t *intro_circ;
  char serviceid[REND_SERVICE_ID_LEN+1];
  char nak_body[1];

  if (circ->purpose != CIRCUIT_PURPOSE_OR || circ->n_conn) {
    warn(LD_PROTOCOL, "Rejecting INTRODUCE1 on non-OR or non-edge circuit %d.",
           circ->p_circ_id);
    goto err;
  }

  /* change to MAX_HEX_NICKNAME_LEN once 0.0.9.x is obsolete */
  if (request_len < (DIGEST_LEN+(MAX_NICKNAME_LEN+1)+REND_COOKIE_LEN+
                     DH_KEY_LEN+CIPHER_KEY_LEN+PKCS1_OAEP_PADDING_OVERHEAD)) {
    warn(LD_PROTOCOL,
         "Impossibly short INTRODUCE1 cell on circuit %d; responding with nack.",
         circ->p_circ_id);
    goto err;
  }

  base32_encode(serviceid, REND_SERVICE_ID_LEN+1, request,10);

  /* The first 20 bytes are all we look at: they have a hash of Bob's PK. */
  intro_circ = circuit_get_next_by_pk_and_purpose(
                             NULL, request, CIRCUIT_PURPOSE_INTRO_POINT);
  if (!intro_circ) {
    info(LD_REND,
         "No intro circ found for INTRODUCE1 cell (%s) from circuit %d; responding with nack.",
         safe_str(serviceid), circ->p_circ_id);
    goto err;
  }

  info(LD_REND,
       "Sending introduction request for service %s from circ %d to circ %d",
       safe_str(serviceid), circ->p_circ_id, intro_circ->p_circ_id);

  /* Great.  Now we just relay the cell down the circuit. */
  if (connection_edge_send_command(NULL, intro_circ,
                                   RELAY_COMMAND_INTRODUCE2,
                                   request, request_len, NULL)) {
    warn(LD_GENERAL,
         "Unable to send INTRODUCE2 cell to Tor client.");
    goto err;
  }
  /* And sent an ack down Alice's circuit.  Empty body means succeeded. */
  if (connection_edge_send_command(NULL,circ,RELAY_COMMAND_INTRODUCE_ACK,
                                   NULL,0,NULL)) {
    warn(LD_GENERAL, "Unable to send INTRODUCE_ACK cell to Tor client.");
    circuit_mark_for_close(circ);
    return -1;
  }

  return 0;
 err:
  /* Send the client an NACK */
  nak_body[0] = 1;
  if (connection_edge_send_command(NULL,circ,RELAY_COMMAND_INTRODUCE_ACK,
                                   nak_body, 1, NULL)) {
    warn(LD_GENERAL, "Unable to send NAK to Tor client.");
    circuit_mark_for_close(circ); /* Is this right? */
  }
  return -1;
}

/** Process an ESTABLISH_RENDEZVOUS cell by setting the circuit's purpose and
 * rendezvous cookie.
 */
int
rend_mid_establish_rendezvous(circuit_t *circ, const char *request, size_t request_len)
{
  char hexid[9];

  if (circ->purpose != CIRCUIT_PURPOSE_OR || circ->n_conn) {
    warn(LD_PROTOCOL, "Tried to establish rendezvous on non-OR or non-edge circuit.");
    goto err;
  }

  if (request_len != REND_COOKIE_LEN) {
    warn(LD_PROTOCOL, "Invalid length on ESTABLISH_RENDEZVOUS.");
    goto err;
  }

  if (circuit_get_rendezvous(request)) {
    warn(LD_PROTOCOL, "Duplicate rendezvous cookie in ESTABLISH_RENDEZVOUS.");
    goto err;
  }

  /* Acknowledge the request. */
  if (connection_edge_send_command(NULL,circ,
                                   RELAY_COMMAND_RENDEZVOUS_ESTABLISHED,
                                   "", 0, NULL)<0) {
    warn(LD_PROTOCOL, "Couldn't send RENDEZVOUS_ESTABLISHED cell.");
    goto err;
  }

  circ->purpose = CIRCUIT_PURPOSE_REND_POINT_WAITING;
  memcpy(circ->rend_cookie, request, REND_COOKIE_LEN);

  base16_encode(hexid,9,request,4);

  info(LD_REND, "Established rendezvous point on circuit %d for cookie %s",
         circ->p_circ_id, hexid);

  return 0;
 err:
  circuit_mark_for_close(circ);
  return -1;
}

/** Process a RENDEZVOUS1 cell by looking up the correct rendezvous
 * circuit by its relaying the cell's body in a RENDEZVOUS2 cell, and
 * connecting the two circuits.
 */
int
rend_mid_rendezvous(circuit_t *circ, const char *request, size_t request_len)
{
  circuit_t *rend_circ;
  char hexid[9];

  base16_encode(hexid,9,request,request_len<4?request_len:4);

  if (request_len>=4) {
    info(LD_REND, "Got request for rendezvous from circuit %d to cookie %s.",
           circ->p_circ_id, hexid);
  }

  if (circ->purpose != CIRCUIT_PURPOSE_OR || circ->n_conn) {
    info(LD_REND,
         "Tried to complete rendezvous on non-OR or non-edge circuit %d.",
         circ->p_circ_id);
    goto err;
  }

  if (request_len != REND_COOKIE_LEN+DH_KEY_LEN+DIGEST_LEN) {
    warn(LD_PROTOCOL,
         "Rejecting RENDEZVOUS1 cell with bad length (%d) on circuit %d.",
         (int)request_len, circ->p_circ_id);
    goto err;
  }

  rend_circ = circuit_get_rendezvous(request);
  if (!rend_circ) {
    warn(LD_PROTOCOL,
         "Rejecting RENDEZVOUS1 cell with unrecognized rendezvous cookie %s.",
         hexid);
    goto err;
  }

  /* Send the RENDEZVOUS2 cell to Alice. */
  if (connection_edge_send_command(NULL, rend_circ,
                                   RELAY_COMMAND_RENDEZVOUS2,
                                   request+REND_COOKIE_LEN,
                                   request_len-REND_COOKIE_LEN, NULL)) {
    warn(LD_GENERAL,
         "Unable to send RENDEZVOUS2 cell to OP on circuit %d.",
         rend_circ->p_circ_id);
    goto err;
  }

  /* Join the circuits. */
  info(LD_REND,
       "Completing rendezvous: circuit %d joins circuit %d (cookie %s)",
       circ->p_circ_id, rend_circ->p_circ_id, hexid);

  circ->purpose = CIRCUIT_PURPOSE_REND_ESTABLISHED;
  rend_circ->purpose = CIRCUIT_PURPOSE_REND_ESTABLISHED;
  memset(circ->rend_cookie, 0, REND_COOKIE_LEN);

  rend_circ->rend_splice = circ;
  circ->rend_splice = rend_circ;

  return 0;
 err:
  circuit_mark_for_close(circ);
  return -1;
}

