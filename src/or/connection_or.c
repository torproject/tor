/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

static int or_handshake_op_send_keys(connection_t *conn);
static int or_handshake_op_finished_sending_keys(connection_t *conn);

static int or_handshake_client_process_auth(connection_t *conn);
static int or_handshake_client_send_auth(connection_t *conn);

static int or_handshake_server_process_auth(connection_t *conn);
static int or_handshake_server_process_nonce(connection_t *conn);

static void connection_or_set_open(connection_t *conn);
static void conn_or_init_crypto(connection_t *conn);

/*
 *
 * these two functions are the main ways 'in' to connection_or
 *
 */

int connection_or_process_inbuf(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_OR);

  if(conn->inbuf_reached_eof) {
    /* eof reached, kill it. */
    log_fn(LOG_DEBUG,"conn reached eof. Closing.");
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
      log_fn(LOG_DEBUG,"called in state where I'm writing. Ignoring buf for now.");
  }

  return 0;
}

int connection_or_finished_flushing(connection_t *conn) {
  int e, len=sizeof(e);

  assert(conn && conn->type == CONN_TYPE_OR);

  switch(conn->state) {
    case OR_CONN_STATE_OP_SENDING_KEYS:
      return or_handshake_op_finished_sending_keys(conn);
    case OR_CONN_STATE_CLIENT_CONNECTING:
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, &e, &len) < 0)  { /* not yet */
        if(errno != EINPROGRESS){
          /* yuck. kill it. */
          log_fn(LOG_DEBUG,"in-progress connect failed. Removing.");
          return -1;
        } else {
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log_fn(LOG_DEBUG,"OR connection to router %s:%u established.",
          conn->address,conn->port);

      if(options.OnionRouter)
        return or_handshake_client_send_auth(conn);
      else
        return or_handshake_op_send_keys(conn);
    case OR_CONN_STATE_CLIENT_SENDING_AUTH:
      log_fn(LOG_DEBUG,"client finished sending auth.");
      conn->state = OR_CONN_STATE_CLIENT_AUTH_WAIT;
      connection_watch_events(conn, POLLIN);
      return 0;
    case OR_CONN_STATE_CLIENT_SENDING_NONCE:
      log_fn(LOG_DEBUG,"client finished sending nonce.");
      conn_or_init_crypto(conn);
      connection_or_set_open(conn);

      return connection_process_inbuf(conn); /* in case there's anything waiting on it */
    case OR_CONN_STATE_SERVER_SENDING_AUTH:
      log_fn(LOG_DEBUG,"server finished sending auth.");
      conn->state = OR_CONN_STATE_SERVER_NONCE_WAIT;
      connection_watch_events(conn, POLLIN);
      return 0;
    case OR_CONN_STATE_OPEN:
      /* FIXME down the road, we'll clear out circuits that are pending to close */
      connection_stop_writing(conn);
      return 0;
    default:
      log_fn(LOG_DEBUG,"BUG: called in unexpected state.");
      return 0;
  }

  return 0;

}

/*********************/

connection_t *connection_or_connect(routerinfo_t *router) {
  connection_t *conn;
  struct sockaddr_in router_addr;
  int s;

  assert(router);

  if(router_is_me(router->addr, router->or_port)) {
    /* this is me! don't connect to me. */
    log(LOG_DEBUG,"connection_or_connect(): This is me. Skipping.");
    return NULL;
  }

  /* this function should never be called if we're already connected to router, but */
  /* check first to be sure */
  conn = connection_exact_get_by_addr_port(router->addr,router->or_port);
  if(conn)
    return conn;

  conn = connection_new(CONN_TYPE_OR);
  if(!conn) {
    return NULL;
  }

  /* set up conn so it's got all the data we need to remember */
  conn->addr = router->addr;
  conn->port = router->or_port;
  conn->bandwidth = router->bandwidth;
  conn->pkey = crypto_pk_dup_key(router->pkey);
  conn->address = strdup(router->address);

  s=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (s < 0) {
    log(LOG_ERR,"Error creating network socket.");
    connection_free(conn);
    return NULL;
  }
  fcntl(s, F_SETFL, O_NONBLOCK); /* set s to non-blocking */

  memset((void *)&router_addr,0,sizeof(router_addr));
  router_addr.sin_family = AF_INET;
  router_addr.sin_port = htons(router->or_port);
  router_addr.sin_addr.s_addr = htonl(router->addr);

  log(LOG_DEBUG,"connection_or_connect() : Trying to connect to %s:%u.",router->address,router->or_port);
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
      conn->state = OR_CONN_STATE_CLIENT_CONNECTING;
      return conn;
    }
  }

  /* it succeeded. we're connected. */
  conn->s = s;

  if(connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn);
    return NULL;
  }

  log(LOG_DEBUG,"connection_or_connect() : Connection to router %s:%u established.",
      router->address, router->or_port);

  if((options.OnionRouter && or_handshake_client_send_auth(conn) >= 0) ||
     (!options.OnionRouter && or_handshake_op_send_keys(conn) >= 0))
    return conn; /* success! */

  /* failure */
  connection_remove(conn);
  connection_free(conn);
  return NULL;
}

/* ********************************** */

int connection_or_create_listener(struct sockaddr_in *bindaddr) {
  log(LOG_DEBUG,"connection_create_or_listener starting");
  return connection_create_listener(bindaddr, CONN_TYPE_OR_LISTENER);
}

int connection_or_handle_listener_read(connection_t *conn) {
  log(LOG_NOTICE,"OR: Received a connection request from a router. Attempting to authenticate.");
  return connection_handle_listener_read(conn, CONN_TYPE_OR, OR_CONN_STATE_SERVER_AUTH_WAIT);
}

/* ***************** */
/* Helper functions to implement handshaking */

#define FLAGS_LEN 2
#define BANDWIDTH_LEN 4
#define KEY_LEN 16
#define ADDR_LEN 4
#define PORT_LEN 2
#define PKEY_LEN 128

static int 
or_handshake_op_send_keys(connection_t *conn) {
  unsigned char message[FLAGS_LEN + BANDWIDTH_LEN + KEY_LEN + KEY_LEN];
  unsigned char cipher[PKEY_LEN];
  int retval;

  assert(conn && conn->type == CONN_TYPE_OR);

  conn->bandwidth = DEFAULT_BANDWIDTH_OP;

  /* generate random keys */
  if(crypto_cipher_generate_key(conn->f_crypto) ||
     crypto_cipher_generate_key(conn->b_crypto)) {
    log(LOG_ERR,"Cannot generate a secure 3DES key.");
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_op_send_keys() : Generated 3DES keys.");
  /* compose the message */
  *(uint16_t *)(message) = htons(HANDSHAKE_AS_OP);
  *(uint32_t *)(message+FLAGS_LEN) = htonl(conn->bandwidth);
  memcpy((void *)(message+FLAGS_LEN+BANDWIDTH_LEN), 
         (void *)conn->f_crypto->key, 16);
  memcpy((void *)(message+FLAGS_LEN+BANDWIDTH_LEN+KEY_LEN), 
         (void *)conn->b_crypto->key, 16);

  /* encrypt with RSA */
  if(crypto_pk_public_encrypt(conn->pkey, message, sizeof(message), cipher, RSA_PKCS1_PADDING) < 0) {
    log(LOG_ERR,"or_handshake_op_send_keys(): Public key encryption failed.");
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_op_send_keys() : Encrypted authentication message.");

  /* send message */

  if(connection_write_to_buf(cipher, PKEY_LEN, conn) < 0) {
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

static int 
or_handshake_op_finished_sending_keys(connection_t *conn) {

  /* do crypto initialization, etc */
  conn_or_init_crypto(conn);

  connection_or_set_open(conn);
  circuit_n_conn_open(conn); /* send the pending onion(s) */
  return 0;
}

static int 
or_handshake_client_send_auth(connection_t *conn) {
  int retval;
  char buf[FLAGS_LEN+ADDR_LEN+PORT_LEN+ADDR_LEN+
           PORT_LEN+KEY_LEN+KEY_LEN+BANDWIDTH_LEN];
  char cipher[PKEY_LEN];
  struct sockaddr_in me; /* my router identity */

  assert(conn);

  if(learn_my_address(&me) < 0)
    return -1;

  /* generate random keys */
  if(crypto_cipher_generate_key(conn->f_crypto) ||
     crypto_cipher_generate_key(conn->b_crypto)) {
    log(LOG_ERR,"Cannot generate a secure DES key.");
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_client_send_auth() : Generated DES keys.");

  /* generate first message */
  *(uint16_t*)buf = htons(HANDSHAKE_AS_OR);
  *(uint32_t*)(buf+FLAGS_LEN) = me.sin_addr.s_addr; /* local address, network order */
  *(uint16_t*)(buf+FLAGS_LEN+ADDR_LEN) = me.sin_port; /* local port, network order */
  *(uint32_t*)(buf+FLAGS_LEN+ADDR_LEN+PORT_LEN) = htonl(conn->addr); /* remote address */
  *(uint16_t*)(buf+FLAGS_LEN+ADDR_LEN+PORT_LEN+ADDR_LEN) = htons(conn->port); /* remote port */
  memcpy(buf+FLAGS_LEN+ADDR_LEN+PORT_LEN+ADDR_LEN+PORT_LEN,
         conn->f_crypto->key,16); /* keys */
  memcpy(buf+FLAGS_LEN+ADDR_LEN+PORT_LEN+ADDR_LEN+PORT_LEN+KEY_LEN,
         conn->b_crypto->key,16);
  *(uint32_t *)(buf+FLAGS_LEN+ADDR_LEN+PORT_LEN+ADDR_LEN+PORT_LEN+
                KEY_LEN+KEY_LEN) = htonl(conn->bandwidth); /* max link utilisation */
  log(LOG_DEBUG,"or_handshake_client_send_auth() : Generated first authentication message.");

  /* encrypt message */
  retval = crypto_pk_public_encrypt(conn->pkey, buf, sizeof(buf), cipher,RSA_PKCS1_PADDING);
  if (retval == -1) /* error */
  { 
    log(LOG_ERR,"Public-key encryption failed during authentication to %s:%u.",conn->address,conn->port);
    log(LOG_DEBUG,"or_handshake_client_send_auth() : Reason : %s.",crypto_perror());
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_client_send_auth() : Encrypted authentication message.");

  /* send message */
  
  if(connection_write_to_buf(cipher, PKEY_LEN, conn) < 0) {
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

static int 
or_handshake_client_process_auth(connection_t *conn) {
  char buf[128]; /* only 56 of this is expected to be used */
  char cipher[128];
  uint32_t bandwidth;
  int retval;
  struct sockaddr_in me; /* my router identity */

  assert(conn);

  if(learn_my_address(&me) < 0)
    return -1;

  if(conn->inbuf_datalen < 128) /* entire response available? */
    return 0; /* not yet */

  if(connection_fetch_from_buf(cipher,128,conn) < 0) {
    return -1;    
  }
  log(LOG_DEBUG,"or_handshake_client_process_auth() : Received auth.");

  /* decrypt response */
  retval = crypto_pk_private_decrypt(get_privatekey(), cipher, 128, buf, RSA_PKCS1_PADDING);
  if (retval == -1)
  { 
    log(LOG_ERR,"Public-key decryption failed during authentication to %s:%u.",
        conn->address,conn->port);
    log(LOG_DEBUG,"or_handshake_client_process_auth() : Reason : %s.",
        crypto_perror());
    return -1;
  }
  else if (retval != 56)
  { 
    log(LOG_ERR,"client_process_auth: incorrect response from router %s:%u.",
        conn->address,conn->port);
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_client_process_auth() : Decrypted response.");
  /* check validity */
  if ( (*(uint32_t*)buf != me.sin_addr.s_addr) || /* local address, network order */
       (*(uint16_t*)(buf+4) != me.sin_port) || /* local port, network order */
       (ntohl(*(uint32_t*)(buf+6)) != conn->addr) || /* remote address */
       (ntohs(*(uint16_t*)(buf+10)) != conn->port) ) { /* remote port */
    log(LOG_ERR,"client_process_auth: Router %s:%u: bad address info.", conn->address,conn->port);
    return -1;
  }
  if ( (memcmp(conn->f_crypto->key, buf+12, 16)) || /* keys */
       (memcmp(conn->b_crypto->key, buf+28, 16)) ) {
    log(LOG_ERR,"client_process_auth: Router %s:%u: bad key info.",conn->address,conn->port);
    return -1;
  }

  log(LOG_DEBUG,"or_handshake_client_process_auth() : Response valid.");

  /* update link info */
  bandwidth = ntohl(*(uint32_t *)(buf+44));

  if (conn->bandwidth > bandwidth)
    conn->bandwidth = bandwidth;

  /* reply is just local addr/port, remote addr/port, nonce */
  memcpy(buf+12, buf+48, 8);

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
  connection_or_set_open(conn);
  return connection_process_inbuf(conn); /* process the rest of the inbuf */

}

/*
 * 
 * auth handshake, as performed by OR *receiving* the connection
 *
 */

static int 
or_handshake_server_process_auth(connection_t *conn) {
  int retval;

  char buf[128]; /* 50 of this is expected to be used for OR, 38 for OP */
  char cipher[128];

  unsigned char iv[16];

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
  retval = crypto_pk_private_decrypt(get_privatekey(), cipher, 128, buf, RSA_PKCS1_PADDING);
  if (retval == -1) {
    log(LOG_ERR,"or_handshake_server_process_auth: Public-key decryption failed.");
    log(LOG_DEBUG,"or_handshake_server_process_auth() : Reason : %s.",
        crypto_perror());
    return -1;
  }

  if (retval == 50) {

    log(LOG_DEBUG,"or_handshake_server_process_auth(): Decrypted OR-style auth message.");
    if(ntohs(*(uint16_t*)buf) != HANDSHAKE_AS_OR) {
      log(LOG_DEBUG,"or_handshake_server_process_auth(): ...but wasn't labelled OR. Dropping.");
      return -1;
    }

    /* identify the router */
    addr = ntohl(*(uint32_t*)(buf+2)); /* save the IP address */
    port = ntohs(*(uint16_t*)(buf+6)); /* save the port */

    router = router_get_by_addr_port(addr,port);
    if (!router) {
      log(LOG_DEBUG,"or_handshake_server_process_auth() : unknown router '%s:%d'. Will drop.", conn->address, port);
      return -1;
    }
    log(LOG_DEBUG,"or_handshake_server_process_auth() : Router identified as %s:%u.",
        router->address,router->or_port);

    if(connection_exact_get_by_addr_port(addr,port)) {
      log(LOG_DEBUG,"or_handshake_server_process_auth(): That router is already connected. Dropping.");
      return -1;
    }

    /* save keys */
    crypto_cipher_set_key(conn->b_crypto,buf+14);
    crypto_cipher_set_key(conn->f_crypto,buf+30);

    /* update link info */
    bandwidth = ntohl(*(uint32_t *)(buf+46));

    conn->bandwidth = router->bandwidth;

    if (conn->bandwidth > bandwidth)
      conn->bandwidth = bandwidth;

    /* copy all relevant info to conn */
    conn->addr = router->addr, conn->port = router->or_port;
    conn->pkey = crypto_pk_dup_key(router->pkey);
    conn->address = strdup(router->address);

    /* generate a nonce */
    retval = crypto_rand(8, conn->nonce);
    if (retval) { /* error */
      log(LOG_ERR,"Cannot generate a nonce.");
      return -1;
    }
    log(LOG_DEBUG,"or_handshake_server_process_auth(): Nonce generated.");

    memmove(buf, buf+2, 44);
    *(uint32_t *)(buf+44) = htonl(conn->bandwidth); /* send max link utilisation */
    memcpy(buf+48,conn->nonce,8); /* append the nonce to the end of the message */

    /* encrypt message */
    retval = crypto_pk_public_encrypt(conn->pkey, buf, 56, cipher,RSA_PKCS1_PADDING);
    if (retval == -1) { /* error */
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

  if(retval == 38) {
    log(LOG_DEBUG,"or_handshake_server_process_auth(): Decrypted OP-style auth message.");
    if(ntohs(*(uint16_t*)buf) != HANDSHAKE_AS_OP) {
      log(LOG_DEBUG,"or_handshake_server_process_auth(): ...but wasn't labelled OP. Dropping.");
      return -1;
    }

    conn->bandwidth = ntohl(*((uint32_t *)(buf+2)));
    log(LOG_DEBUG,"or_handshake_server_process_auth(): Bandwidth %d requested.",conn->bandwidth);

    crypto_cipher_set_key(conn->b_crypto, buf+6);
    crypto_cipher_set_key(conn->f_crypto, buf+22);

    memset(iv, 0, 16);
    crypto_cipher_set_iv(conn->b_crypto, iv);
    crypto_cipher_set_iv(conn->f_crypto, iv);

    crypto_cipher_encrypt_init_cipher(conn->b_crypto);
    crypto_cipher_decrypt_init_cipher(conn->f_crypto);

    conn->state = OR_CONN_STATE_OPEN;
    connection_init_timeval(conn);
    connection_watch_events(conn, POLLIN);

    return connection_process_inbuf(conn); /* in case they sent some cells along with the keys */
  }

  log(LOG_ERR,"or_handshake_server_process_auth(): received an incorrect authentication request.");
  return -1;
}

static int 
or_handshake_server_process_nonce(connection_t *conn) {

  char buf[128];
  char cipher[128];
  int retval;
  struct sockaddr_in me; /* my router identity */

  assert(conn);

  if(learn_my_address(&me) < 0)
    return -1;

  if(conn->inbuf_datalen < 128) /* entire response available? */
    return 0; /* not yet */

  if(connection_fetch_from_buf(cipher,128,conn) < 0) {
    return -1;    
  }
  log(LOG_DEBUG,"or_handshake_server_process_nonce() : Received auth.");

  /* decrypt response */
  retval = crypto_pk_private_decrypt(get_privatekey(), cipher, 128, buf,RSA_PKCS1_PADDING);
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
    log(LOG_ERR,"server_process_nonce: incorrect response from router %s:%u.",
        conn->address,conn->port);
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_server_process_nonce() : Response decrypted.");

  /* check validity */
  if ((ntohl(*(uint32_t*)buf) != conn->addr) || /* remote address */
      (ntohs(*(uint16_t*)(buf+4)) != conn->port) || /* remote port */ 
       (*(uint32_t*)(buf+6) != me.sin_addr.s_addr) || /* local address, network order */
       (*(uint16_t*)(buf+10) != me.sin_port) || /* local port, network order */
      (memcmp(conn->nonce,buf+12,8))) /* nonce */
  { 
    log(LOG_ERR,"server_process_nonce: Router %s:%u gave bad response.",conn->address,conn->port);
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_server_process_nonce() : Response valid. Authentication complete.");

  conn_or_init_crypto(conn);
  connection_or_set_open(conn);
  return connection_process_inbuf(conn); /* process the rest of the inbuf */

}

/*********************/

static void 
connection_or_set_open(connection_t *conn) {
  conn->state = OR_CONN_STATE_OPEN;
  directory_set_dirty();
  connection_init_timeval(conn);
  connection_watch_events(conn, POLLIN);
}

static void 
conn_or_init_crypto(connection_t *conn) {
  //int x;
  unsigned char iv[16];

  assert(conn);

  memset((void *)iv, 0, 16);
  crypto_cipher_set_iv(conn->f_crypto, iv);
  crypto_cipher_set_iv(conn->b_crypto, iv);

  crypto_cipher_encrypt_init_cipher(conn->f_crypto);
  crypto_cipher_decrypt_init_cipher(conn->b_crypto);
    /* always encrypt with f, always decrypt with b */
}



/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
