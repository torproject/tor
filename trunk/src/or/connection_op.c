/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

int connection_op_process_inbuf(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_OP);

  if(conn->inbuf_reached_eof) {
    /* eof reached, kill it. */
    log(LOG_DEBUG,"connection_op_process_inbuf(): conn reached eof. Closing.");
    return -1;
  }

  log(LOG_DEBUG,"connection_op_process_inbuf(): state %d.",conn->state);

  switch(conn->state) {
    case OP_CONN_STATE_AWAITING_KEYS:
      return op_handshake_process_keys(conn);
    case OP_CONN_STATE_OPEN:
      return connection_process_cell_from_inbuf(conn);
    default:
      log(LOG_DEBUG,"connection_op_process_inbuf() called in state where I'm writing. Ignoring buf for now.")
;
  }

  return 0;

}

int op_handshake_process_keys(connection_t *conn) {
  int retval;
  int x;

  /* key exchange message */
  unsigned char auth_cipher[128];
  unsigned char auth_plain[128];

  assert(conn);

  log(LOG_DEBUG,"op_handshake_process_keys() entered.");

  if(conn->inbuf_datalen < 128) /* entire response available? */
    return 0; /* not yet */

  if(connection_fetch_from_buf(auth_cipher,128,conn) < 0) {
    return -1;
  }
  log(LOG_DEBUG,"op_handshake_process_keys() : Received auth.");

  /* decrypt response */
  retval = RSA_private_decrypt(128,auth_cipher,auth_plain,conn->prkey,RSA_PKCS1_PADDING);
  if (retval == -1)
  { 
    log(LOG_ERR,"Decrypting keys from new OP failed.");
    log(LOG_DEBUG,"op_handshake_process_keys() : Reason : %s.",
        ERR_reason_error_string(ERR_get_error()));
    return -1;
  }

  log(LOG_DEBUG,"Successfully decrypted keys from new OP.");

  conn->bandwidth = ntohl(*((uint32_t *)auth_plain));

  memcpy(conn->b_session_key, auth_plain+4, 8);
  memcpy(conn->f_session_key, auth_plain+12, 8);
  printf("f_session_key: ");
  for(x=0;x<8;x++) {
    printf("%d ",conn->f_session_key[x]);
  }
  printf("\nb_session_key: ");
  for(x=0;x<8;x++) {
    printf("%d ",conn->b_session_key[x]);
  }
  printf("\n");

  memset((void *)conn->f_session_iv, 0, 8);
  memset((void *)conn->b_session_iv, 0, 8);

  EVP_CIPHER_CTX_init(&conn->f_ctx);
  EVP_CIPHER_CTX_init(&conn->b_ctx);
  EVP_EncryptInit(&conn->b_ctx, EVP_des_ofb(), conn->b_session_key, conn->b_session_iv);
  EVP_DecryptInit(&conn->f_ctx, EVP_des_ofb(), conn->f_session_key, conn->f_session_iv);

  conn->state = OP_CONN_STATE_OPEN;
  connection_init_timeval(conn);
  connection_watch_events(conn, POLLIN);

  return 0;
}

int connection_op_finished_flushing(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_OP);

  switch(conn->state) {
    case OP_CONN_STATE_OPEN:
      /* FIXME down the road, we'll clear out circuits that are pending to close */
      connection_stop_writing(conn);
      return 0;
    default:
      log(LOG_DEBUG,"Bug: connection_op_finished_flushing() called in unexpected state.");
      return 0;
  }

  return 0;

}

int connection_op_create_listener(RSA *prkey, struct sockaddr_in *local) {
  log(LOG_DEBUG,"connection_create_op_listener starting");
  return connection_create_listener(prkey, local, CONN_TYPE_OP_LISTENER);
}

int connection_op_handle_listener_read(connection_t *conn) {
  log(LOG_NOTICE,"OP: Received a connection request. Waiting for keys.");
  return connection_handle_listener_read(conn, CONN_TYPE_OP, OP_CONN_STATE_AWAITING_KEYS);
} 

