/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/* 
 *
 * these two functions are the main ways 'in' to connection_or
 *
 */

int connection_or_process_inbuf(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_OR);

  if(conn->inbuf_reached_eof) {
    /* eof reached, kill it. */
    log(LOG_DEBUG,"connection_or_process_inbuf(): conn reached eof. Closing.");
    return -1;
  }

//  log(LOG_DEBUG,"connection_or_process_inbuf(): state %d.",conn->state);

  switch(conn->state) {
    case OR_CONN_STATE_CLIENT_AUTH_WAIT:
      return or_handshake_client_process_auth(conn);
    case OR_CONN_STATE_SERVER_AUTH_WAIT:
      return or_handshake_server_process_auth(conn);
    case OR_CONN_STATE_SERVER_NONCE_WAIT:
      return or_handshake_server_process_nonce(conn);
    case OR_CONN_STATE_OPEN:
      return connection_process_cell_from_inbuf(conn);
    default:
      log(LOG_DEBUG,"connection_or_process_inbuf() called in state where I'm writing. Ignoring buf for now.");
  }

  return 0;
}

int connection_or_finished_flushing(connection_t *conn) {
  int e, len=sizeof(e);

  assert(conn && conn->type == CONN_TYPE_OR);

  switch(conn->state) {
    case OR_CONN_STATE_OP_CONNECTING:
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, &e, &len) < 0)  { /* not yet */
        if(errno != EINPROGRESS){
          /* yuck. kill it. */
          log(LOG_DEBUG,"connection_or_finished_flushing(): in-progress connect failed. Removing.");
          return -1;
        } else {
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log(LOG_DEBUG,"connection_or_finished_flushing() : OP connection to router %s:%u established.",
          conn->address,conn->port);

      return or_handshake_op_send_keys(conn);
    case OR_CONN_STATE_OP_SENDING_KEYS:
      return or_handshake_op_finished_sending_keys(conn);
    case OR_CONN_STATE_CLIENT_CONNECTING:
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, &e, &len) < 0)  { /* not yet */
        if(errno != EINPROGRESS){
          /* yuck. kill it. */
          log(LOG_DEBUG,"connection_or_finished_flushing(): in-progress connect failed. Removing.");	
          return -1;
        } else {
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log(LOG_DEBUG,"connection_or_finished_flushing() : OR connection to router %s:%u established.",
          conn->address,conn->port);

      return or_handshake_client_send_auth(conn);
    case OR_CONN_STATE_CLIENT_SENDING_AUTH:
      log(LOG_DEBUG,"connection_or_finished_flushing(): client finished sending auth.");
      conn->state = OR_CONN_STATE_CLIENT_AUTH_WAIT;
      connection_watch_events(conn, POLLIN);
      return 0;
    case OR_CONN_STATE_CLIENT_SENDING_NONCE:
      log(LOG_DEBUG,"connection_or_finished_flushing(): client finished sending nonce.");
      conn_or_init_crypto(conn);
      conn->state = OR_CONN_STATE_OPEN;
      connection_init_timeval(conn);
      connection_watch_events(conn, POLLIN);
      return 0;
    case OR_CONN_STATE_SERVER_SENDING_AUTH:
      log(LOG_DEBUG,"connection_or_finished_flushing(): server finished sending auth.");
      conn->state = OR_CONN_STATE_SERVER_NONCE_WAIT;
      connection_watch_events(conn, POLLIN);
      return 0;
    case OR_CONN_STATE_OPEN:
      /* FIXME down the road, we'll clear out circuits that are pending to close */
      connection_stop_writing(conn);
      return 0;
    default:
      log(LOG_DEBUG,"Bug: connection_or_finished_flushing() called in unexpected state.");
      return 0;
  }

  return 0;

}

/*********************/

void conn_or_init_crypto(connection_t *conn) {
  //int x;
  unsigned char iv[16];

  assert(conn);
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

  memset((void *)iv, 0, 16);
  crypto_cipher_set_iv(conn->f_crypto, iv);
  crypto_cipher_set_iv(conn->b_crypto, iv);
  
  crypto_cipher_encrypt_init_cipher(conn->f_crypto);
  crypto_cipher_decrypt_init_cipher(conn->b_crypto);
    /* always encrypt with f, always decrypt with b */
  
}

/* helper function for connection_or_connect_as_or and _as_op.
 * returns NULL if the connection fails. If it succeeds, it sets
 * *result to 1 if connect() returned before completing, or to 2
 * if it completed, and returns the new conn.
 */
connection_t *connection_or_connect(routerinfo_t *router, crypto_pk_env_t *prkey, struct sockaddr_in *local, 
                                    uint16_t port, int *result) {
  connection_t *conn;
  struct sockaddr_in router_addr;
  int s;

  conn = connection_new(CONN_TYPE_OR);
  if(!conn)
    return NULL;

  /* set up conn so it's got all the data we need to remember */
  conn->addr = router->addr, conn->port = router->or_port; /* NOTE we store or_port here always */
  conn->prkey = prkey;
  conn->bandwidth = router->min; /* kludge, should make a router->bandwidth and use that */
  conn->pkey = router->pkey;
  conn->address = strdup(router->address);
  memcpy(&conn->local,local,sizeof(struct sockaddr_in));

  s=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s < 0)
  { 
    log(LOG_ERR,"Error creating network socket.");
    connection_free(conn);
    return NULL;
  }
  fcntl(s, F_SETFL, O_NONBLOCK); /* set s to non-blocking */

  memset((void *)&router_addr,0,sizeof(router_addr));
  router_addr.sin_family = AF_INET;
  router_addr.sin_port = htons(port);
  router_addr.sin_addr.s_addr = router->addr;

  log(LOG_DEBUG,"connection_or_connect() : Trying to connect to %s:%u.",inet_ntoa(*(struct in_addr *)&router->addr),port);

  if(connect(s,(struct sockaddr *)&router_addr,sizeof(router_addr)) < 0){
    if(errno != EINPROGRESS){
      /* yuck. kill it. */
      connection_free(conn);
      return NULL;
    } else {
      /* it's in progress. set state appropriately and return. */
      conn->s = s;

      if(connection_add(conn) < 0) { /* no space, forget it */
        connection_free(conn);
        return NULL;
      }

      log(LOG_DEBUG,"connection_or_connect() : connect in progress.");
      connection_watch_events(conn, POLLIN | POLLOUT); /* writable indicates finish, readable indicates broken link */
      *result = 1; /* connecting */
      return conn;

    }
  }

  /* it succeeded. we're connected. */
  conn->s = s;

  if(connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn);
    return NULL;
  }

  log(LOG_DEBUG,"connection_or_connect() : Connection to router %s:%u established.",router->address,port);

  *result = 2; /* connection finished */
  return(conn);
}

/*
 *
 * handshake for connecting to the op_port of an onion router
 *
 */

connection_t *connection_or_connect_as_op(routerinfo_t *router, struct sockaddr_in *local) {
  connection_t *conn;
  int result=0; /* so connection_or_connect() can tell us what happened */

  assert(router && local);

  if(router->addr == local->sin_addr.s_addr && router->or_port == ntohs(local->sin_port)) {
    /* this is me! don't connect to me. */
    log(LOG_WARNING,"connection_or_connect_as_op(): You just asked me to connect to myself.");
    return NULL;
  }

  /* this function should never be called if we're already connected to router, but */
  /* check first to be sure */
  conn = connection_exact_get_by_addr_port(router->addr,router->or_port);
  if(conn)
    return conn;

  conn = connection_or_connect(router, NULL, local, router->op_port, &result);
  if(!conn)
    return NULL;

  assert(result != 0); /* if conn is defined, then it must have set result */

  /* now we know it succeeded */
  if(result == 1) {
    conn->state = OR_CONN_STATE_OP_CONNECTING;
    return conn;
  }

  if(result == 2) {
    /* move to the next step in the handshake */
    if(or_handshake_op_send_keys(conn) < 0) {
      connection_remove(conn);
      connection_free(conn);
      return NULL;
    }
    return conn;
  }
  return NULL; /* shouldn't get here; to keep gcc happy */
}

int or_handshake_op_send_keys(connection_t *conn) {
  //int x;
  uint32_t bandwidth = DEFAULT_BANDWIDTH_OP;
  unsigned char message[20]; /* bandwidth(32bits), forward key(64bits), backward key(64bits) */
  unsigned char cipher[128];
  int retval;

  assert(conn && conn->type == CONN_TYPE_OR);

  /* generate random keys */
  if(crypto_cipher_generate_key(conn->f_crypto) ||
     crypto_cipher_generate_key(conn->b_crypto)) {
    log(LOG_ERR,"Cannot generate a secure DES key.");
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_op_send_keys() : Generated DES keys.");
  /* compose the message */
  *(uint32_t *)message = htonl(bandwidth);
  memcpy((void *)(message + 4), (void *)conn->f_crypto->key, 8);
  memcpy((void *)(message + 12), (void *)conn->b_crypto->key, 8);

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

  /* encrypt with RSA */
  if(crypto_pk_public_encrypt(conn->pkey, message, 20, cipher, RSA_PKCS1_PADDING) < 0) {
    log(LOG_ERR,"or_handshake_op_send_keys(): Public key encryption failed.");
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_op_send_keys() : Encrypted authentication message.");

  /* send message */

  if(connection_write_to_buf(cipher, 128, conn) < 0) {
    log(LOG_DEBUG,"or_handshake_op_send_keys(): my outbuf is full. Oops.");
    return -1;
  }
  retval = connection_flush_buf(conn);
  if(retval < 0) {
    log(LOG_DEBUG,"or_handshake_op_send_keys(): bad socket while flushing.");
    return -1;
  }
  if(retval > 0) {
    /* still stuff on the buffer. */
    conn->state = OR_CONN_STATE_OP_SENDING_KEYS;
    connection_watch_events(conn, POLLOUT | POLLIN);
    return 0;
  }

  /* it finished sending */
  log(LOG_DEBUG,"or_handshake_op_send_keys(): Finished sending authentication message.");
  return or_handshake_op_finished_sending_keys(conn);
}

int or_handshake_op_finished_sending_keys(connection_t *conn) {

  /* do crypto initialization, etc */
  conn_or_init_crypto(conn);

  conn->state = OR_CONN_STATE_OPEN;
  connection_init_timeval(conn);
  connection_watch_events(conn, POLLIN); /* give it a default, tho the ap_handshake call may change it */
  ap_handshake_n_conn_open(conn); /* send the pending onion */
  return 0;

}

/*
 *
 * auth handshake, as performed by OR *initiating* the connection
 *
 */

connection_t *connection_or_connect_as_or(routerinfo_t *router, crypto_pk_env_t *prkey, struct sockaddr_in *local) {
  connection_t *conn;
  int result=0; /* so connection_or_connect() can tell us what happened */

  assert(router && prkey && local);

  if(router->addr == local->sin_addr.s_addr && router->or_port == ntohs(local->sin_port)) {
    /* this is me! don't connect to me. */
    log(LOG_DEBUG,"connection_or_connect_as_or(): This is me. Skipping.");
    return NULL;
  }

  conn = connection_or_connect(router, prkey, local, router->or_port, &result);
  if(!conn)
    return NULL;

  /* now we know it succeeded */
  if(result == 1) {
    conn->state = OR_CONN_STATE_CLIENT_CONNECTING;
    return conn;
  }

  if(result == 2) {
    /* move to the next step in the handshake */
    if(or_handshake_client_send_auth(conn) < 0) {
      connection_remove(conn);
      connection_free(conn);
      return NULL;
    }
    return conn; 
  }
  return NULL; /* shouldn't get here; to keep gcc happy */
}

int or_handshake_client_send_auth(connection_t *conn) {
  int retval;
  char buf[44];
  char cipher[128];

  assert(conn);

  /* generate random keys */
  if(crypto_cipher_generate_key(conn->f_crypto) ||
     crypto_cipher_generate_key(conn->b_crypto)) {
    log(LOG_ERR,"Cannot generate a secure DES key.");
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_client_send_auth() : Generated DES keys.");

  /* generate first message */
  *(uint32_t*)buf = htonl(conn->local.sin_addr.s_addr); /* local address */
  *(uint16_t*)(buf+4) = conn->local.sin_port; /* local port, already network order */
  *(uint32_t*)(buf+6) = htonl(conn->addr); /* remote address */
  *(uint16_t*)(buf+10) = htons(conn->port); /* remote port */
  memcpy(buf+12,conn->f_crypto->key,8); /* keys */
  memcpy(buf+20,conn->b_crypto->key,8);
  *(uint32_t *)(buf+28) = htonl(conn->bandwidth); /* max link utilisation */
  log(LOG_DEBUG,"or_handshake_client_send_auth() : Generated first authentication message.");

  /* encrypt message */
  retval = crypto_pk_public_encrypt(conn->pkey, buf, 36, cipher,RSA_PKCS1_PADDING);
  if (retval == -1) /* error */
  { 
    log(LOG_ERR,"Public-key encryption failed during authentication to %s:%u.",conn->address,conn->port);
    log(LOG_DEBUG,"or_handshake_client_send_auth() : Reason : %s.",crypto_perror());
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_client_send_auth() : Encrypted authentication message.");

  /* send message */
  
  if(connection_write_to_buf(cipher, 128, conn) < 0) {
    log(LOG_DEBUG,"or_handshake_client_send_auth(): my outbuf is full. Oops.");
    return -1;
  }
  retval = connection_flush_buf(conn);
  if(retval < 0) {
    log(LOG_DEBUG,"or_handshake_client_send_auth(): bad socket while flushing.");
    return -1;
  }
  if(retval > 0) {
    /* still stuff on the buffer. */
    conn->state = OR_CONN_STATE_CLIENT_SENDING_AUTH;
    connection_watch_events(conn, POLLOUT | POLLIN);
    return 0;
  }

  /* it finished sending */
  log(LOG_DEBUG,"or_handshake_client_send_auth(): Finished sending authentication message.");
  conn->state = OR_CONN_STATE_CLIENT_AUTH_WAIT;
  connection_watch_events(conn, POLLIN);
  return 0;

}

int or_handshake_client_process_auth(connection_t *conn) {
  char buf[128]; /* only 44 of this is expected to be used */
  char cipher[128];
  uint32_t bandwidth;
  int retval;

  assert(conn);

  if(conn->inbuf_datalen < 128) /* entire response available? */
    return 0; /* not yet */

  if(connection_fetch_from_buf(cipher,128,conn) < 0) {
    return -1;    
  }
  log(LOG_DEBUG,"or_handshake_client_process_auth() : Received auth.");

  /* decrypt response */
  retval = crypto_pk_private_decrypt(conn->prkey, cipher, 128, buf, RSA_PKCS1_PADDING);
  if (retval == -1)
  { 
    log(LOG_ERR,"Public-key decryption failed during authentication to %s:%u.",
        conn->address,conn->port);
    log(LOG_DEBUG,"or_handshake_client_process_auth() : Reason : %s.",
        crypto_perror());
    return -1;
  }
  else if (retval != 44)
  { 
    log(LOG_ERR,"Received an incorrect response from router %s:%u during authentication.",
        conn->address,conn->port);
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_client_process_auth() : Decrypted response.");
  /* check validity */
  if ( (ntohl(*(uint32_t*)buf) != conn->local.sin_addr.s_addr) || /* local address */
        (*(uint16_t*)(buf+4) != conn->local.sin_port) || /* local port, keep network order */
       (ntohl(*(uint32_t*)(buf+6)) != conn->addr) || /* remote address */
       (ntohs(*(uint16_t*)(buf+10)) != conn->port) || /* remote port */
       (memcmp(conn->f_crypto->key, buf+12, 8)) || /* keys */
       (memcmp(conn->b_crypto->key, buf+20, 8)) )
  { /* incorrect response */
    log(LOG_ERR,"Router %s:%u failed to authenticate. Either the key I have is obsolete or they're doing something they're not supposed to.",conn->address,conn->port);
    return -1;
  }

  log(LOG_DEBUG,"or_handshake_client_process_auth() : Response valid.");

  /* update link info */
  bandwidth = ntohl(*(uint32_t *)(buf+28));

  if (conn->bandwidth > bandwidth)
    conn->bandwidth = bandwidth;

  /* reply is just local addr/port, remote addr/port, nonce */
  memcpy(buf+12, buf+36, 8);

  /* encrypt reply */
  retval = crypto_pk_public_encrypt(conn->pkey, buf, 20, cipher,RSA_PKCS1_PADDING);
  if (retval == -1) /* error */
  { 
    log(LOG_ERR,"Public-key encryption failed during authentication to %s:%u.",conn->address,conn->port);
    log(LOG_DEBUG,"or_handshake_client_process_auth() : Reason : %s.",crypto_perror());
    return -1;
  }

  /* send the message */

  if(connection_write_to_buf(cipher, 128, conn) < 0) {
    log(LOG_DEBUG,"or_handshake_client_process_auth(): my outbuf is full. Oops.");
    return -1;
  }
  retval = connection_flush_buf(conn);
  if(retval < 0) {
    log(LOG_DEBUG,"or_handshake_client_process_auth(): bad socket while flushing.");
    return -1;
  }
  if(retval > 0) {
    /* still stuff on the buffer. */
    conn->state = OR_CONN_STATE_CLIENT_SENDING_NONCE;
    connection_watch_events(conn, POLLOUT | POLLIN);
/*    return(connection_process_inbuf(conn)); process the rest of the inbuf */
    return 0;   
  }

  /* it finished sending */
  log(LOG_DEBUG,"or_handshake_client_process_auth(): Finished sending nonce.");
  conn_or_init_crypto(conn);
  conn->state = OR_CONN_STATE_OPEN;
  connection_init_timeval(conn);
  connection_watch_events(conn, POLLIN);
  return connection_process_inbuf(conn); /* process the rest of the inbuf */

}

/*
 * 
 * auth handshake, as performed by OR *receiving* the connection
 *
 */

int or_handshake_server_process_auth(connection_t *conn) {
  int retval;

  char buf[128]; /* only 42 of this is expected to be used */
  char cipher[128];

  uint32_t addr;
  uint16_t port;

  uint32_t bandwidth;
  routerinfo_t *router;

  assert(conn);

  log(LOG_DEBUG,"or_handshake_server_process_auth() entered.");

  if(conn->inbuf_datalen < 128) /* entire response available? */
    return 0; /* not yet */  

  if(connection_fetch_from_buf(cipher,128,conn) < 0) {
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_server_process_auth() : Received auth.");

  /* decrypt response */
  retval = crypto_pk_private_decrypt(conn->prkey, cipher, 128, buf, RSA_PKCS1_PADDING);
  if (retval == -1)
  { 
    log(LOG_ERR,"Public-key decryption failed processing auth message from new client.");
    log(LOG_DEBUG,"or_handshake_server_process_auth() : Reason : %s.",
        crypto_perror());
    return -1;
  }
  else if (retval != 36)
  { 
    log(LOG_ERR,"Received an incorrect authentication request.");
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_server_process_auth() : Decrypted authentication message.");

  /* identify the router */
  addr = ntohl(*(uint32_t*)buf); /* save the IP address */
  port = ntohs(*(uint16_t*)(buf+4)); /* save the port */

  router = router_get_by_addr_port(addr,port);
  if (!router)
  {
    log(LOG_DEBUG,"or_handshake_server_process_auth() : Received a connection from an unknown router. Will drop.");
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_server_process_auth() : Router identified as %s:%u.",
      router->address,router->or_port);

  if(connection_exact_get_by_addr_port(addr,port)) {
    log(LOG_DEBUG,"or_handshake_server_process_auth(): That router is already connected. Dropping.");
    return -1;
  }

  /* save keys */
  crypto_cipher_set_key(conn->b_crypto,buf+12);
  crypto_cipher_set_key(conn->f_crypto,buf+20);

  /* update link info */
  bandwidth = ntohl(*(uint32_t *)(buf+28));

  conn->bandwidth = router->min; /* FIXME, should make a router->bandwidth and use that */

  if (conn->bandwidth > bandwidth)
    conn->bandwidth = bandwidth;

  /* copy all relevant info to conn */
  conn->addr = router->addr, conn->port = router->or_port;
  conn->pkey = router->pkey;
  conn->address = strdup(router->address);

  /* generate a nonce */
  retval = crypto_pseudo_rand(8, conn->nonce);
  if (retval) /* error */
  {
    log(LOG_ERR,"Cannot generate a nonce.");
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_server_process_auth() : Nonce generated.");

  /* generate message */
  memcpy(buf+36,conn->nonce,8); /* append the nonce to the end of the message */
  *(uint32_t *)(buf+28) = htonl(conn->bandwidth); /* send max link utilisation */

  /* encrypt message */
  retval = crypto_pk_public_encrypt(conn->pkey, buf, 44, cipher,RSA_PKCS1_PADDING);
  if (retval == -1) /* error */
  {
    log(LOG_ERR,"Public-key encryption failed during authentication to %s:%u.",conn->address,conn->port);
    log(LOG_DEBUG,"or_handshake_server_process_auth() : Reason : %s.",crypto_perror());
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_server_process_auth() : Reply encrypted.");

  /* send message */

  if(connection_write_to_buf(cipher, 128, conn) < 0) {
    log(LOG_DEBUG,"or_handshake_server_process_auth(): my outbuf is full. Oops.");
    return -1;
  }
  retval = connection_flush_buf(conn);
  if(retval < 0) {
    log(LOG_DEBUG,"or_handshake_server_process_auth(): bad socket while flushing.");
    return -1;
  }
  if(retval > 0) {
    /* still stuff on the buffer. */
    conn->state = OR_CONN_STATE_SERVER_SENDING_AUTH;
    connection_watch_events(conn, POLLOUT | POLLIN);
    return 0;
  }

  /* it finished sending */
  log(LOG_DEBUG,"or_handshake_server_process_auth(): Finished sending auth.");
  conn->state = OR_CONN_STATE_SERVER_NONCE_WAIT;
  connection_watch_events(conn, POLLIN);
  return 0;

}

int or_handshake_server_process_nonce(connection_t *conn) {

  char buf[128];
  char cipher[128];
  int retval;

  assert(conn);

  if(conn->inbuf_datalen < 128) /* entire response available? */
    return 0; /* not yet */

  if(connection_fetch_from_buf(cipher,128,conn) < 0) {
    return -1;    
  }
  log(LOG_DEBUG,"or_handshake_server_process_nonce() : Received auth.");

  /* decrypt response */
  retval = crypto_pk_private_decrypt(conn->prkey, cipher, 128, buf,RSA_PKCS1_PADDING);
  if (retval == -1)
  {
    log(LOG_ERR,"Public-key decryption failed during authentication to %s:%u.",
        conn->address,conn->port);
    log(LOG_DEBUG,"or_handshake_server_process_nonce() : Reason : %s.",
        crypto_perror());
    return -1;
  }
  else if (retval != 20)
  { 
    log(LOG_ERR,"Received an incorrect response from router %s:%u during authentication.",
        conn->address,conn->port);
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_server_process_nonce() : Response decrypted.");

  /* check validity */
  if ((ntohl(*(uint32_t*)buf) != conn->addr) || /* remote address */
      (ntohs(*(uint16_t*)(buf+4)) != conn->port) || /* remote port */ 
      (ntohl(*(uint32_t*)(buf+6)) != conn->local.sin_addr.s_addr) || /* local address */
       (*(uint16_t*)(buf+10) != conn->local.sin_port) || /* local port, network order */
      (memcmp(conn->nonce,buf+12,8))) /* nonce */
  { 
    log(LOG_ERR,"Router %s:%u failed to authenticate. Either the key I have is obsolete or they're doing something they're not supposed to.",conn->address,conn->port);
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_server_process_nonce() : Response valid. Authentication complete.");

  conn_or_init_crypto(conn);
  conn->state = OR_CONN_STATE_OPEN;
  connection_init_timeval(conn);
  connection_watch_events(conn, POLLIN);
  return connection_process_inbuf(conn); /* process the rest of the inbuf */

}


/* ********************************** */


int connection_or_create_listener(crypto_pk_env_t *prkey, struct sockaddr_in *local) {
  log(LOG_DEBUG,"connection_create_or_listener starting");
  return connection_create_listener(prkey, local, CONN_TYPE_OR_LISTENER);
}

int connection_or_handle_listener_read(connection_t *conn) {
  log(LOG_NOTICE,"OR: Received a connection request from a router. Attempting to authenticate.");
  return connection_handle_listener_read(conn, CONN_TYPE_OR, OR_CONN_STATE_SERVER_AUTH_WAIT);
}

