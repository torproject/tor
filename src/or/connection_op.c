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
  //int x;
  unsigned char iv[16];

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
  retval = crypto_pk_private_decrypt(getprivatekey(), auth_cipher, 128, auth_plain,RSA_PKCS1_PADDING);
  if (retval == -1)
  { 
    log(LOG_ERR,"Decrypting keys from new OP failed.");
    log(LOG_DEBUG,"op_handshake_process_keys() : Reason : %s.",
        crypto_perror());
    return -1;
  }
  /* XXXX Check length */

  log(LOG_DEBUG,"Successfully decrypted keys from new OP.");

  conn->bandwidth = ntohl(*((uint32_t *)auth_plain));
  log(LOG_DEBUG,"op_handshake_process_keys(): Bandwidth %d requested.",conn->bandwidth);

  crypto_cipher_set_key(conn->b_crypto, auth_plain+4);
  crypto_cipher_set_key(conn->f_crypto, auth_plain+20);
#if 0
  printf("f_session_key: ");
  for(x=0;x<8;x++) {
    printf("%d ",conn->f_crypto->key[x]);
  }
  printf("\nb_session_key: ");
  for(x=0;x<8;x++) {
    printf("%d ",conn->b_crypto->key[x]);
  }
  printf("\n");
#endif
  
  memset(iv, 0, 16);
  crypto_cipher_set_iv(conn->b_crypto, iv);
  crypto_cipher_set_iv(conn->f_crypto, iv);

  crypto_cipher_encrypt_init_cipher(conn->b_crypto);
  crypto_cipher_decrypt_init_cipher(conn->f_crypto);

  conn->state = OP_CONN_STATE_OPEN;
  connection_init_timeval(conn);
  connection_watch_events(conn, POLLIN);

  return connection_process_inbuf(conn); /* in case they sent some cells along with the keys */
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

int connection_op_create_listener(struct sockaddr_in *bindaddr) {
  log(LOG_DEBUG,"connection_create_op_listener starting");
  return connection_create_listener(bindaddr, CONN_TYPE_OP_LISTENER);
}

int connection_op_handle_listener_read(connection_t *conn) {
  log(LOG_NOTICE,"OP: Received a connection request. Waiting for keys.");
  return connection_handle_listener_read(conn, CONN_TYPE_OP, OP_CONN_STATE_AWAITING_KEYS);
} 

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
