/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

#ifndef USE_TLS
static int or_handshake_op_send_keys(connection_t *conn);
static int or_handshake_op_finished_sending_keys(connection_t *conn);

static int or_handshake_client_process_auth(connection_t *conn);
static int or_handshake_client_send_auth(connection_t *conn);

static int or_handshake_server_process_auth(connection_t *conn);
static int or_handshake_server_process_nonce(connection_t *conn);

static void conn_or_init_crypto(connection_t *conn);
static void connection_or_set_open(connection_t *conn);
#endif

/*
 *
 * these two functions are the main ways 'in' to connection_or
 *
 */

int connection_or_process_inbuf(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_OR);

  if(conn->inbuf_reached_eof) {
    log_fn(LOG_DEBUG,"conn reached eof. Closing.");
    return -1;
  }

#ifdef USE_TLS
  if(conn->state != OR_CONN_STATE_OPEN)
    return 0; /* don't do anything */
  return connection_process_cell_from_inbuf(conn);
#else
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
#endif
}

int connection_or_finished_flushing(connection_t *conn) {
  int e, len=sizeof(e);

  assert(conn && conn->type == CONN_TYPE_OR);

  switch(conn->state) {
#ifndef USE_TLS
    case OR_CONN_STATE_OP_SENDING_KEYS:
      return or_handshake_op_finished_sending_keys(conn);
    case OR_CONN_STATE_CLIENT_CONNECTING:
#else
    case OR_CONN_STATE_CONNECTING:
#endif
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, (void*)&e, &len) < 0)  { /* not yet */
        if(!ERRNO_CONN_EINPROGRESS(errno)){
          log_fn(LOG_DEBUG,"in-progress connect failed. Removing.");
          return -1;
        } else {
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log_fn(LOG_DEBUG,"OR connect() to router %s:%u finished.",
          conn->address,conn->port);

#ifdef USE_TLS
      if(connection_tls_start_handshake(conn, 0) < 0)
        return -1;
#else
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
#endif
    case OR_CONN_STATE_OPEN:
      connection_stop_writing(conn);
      return 0;
    default:
      log_fn(LOG_ERR,"BUG: called in unexpected state.");
      return 0;
  }
}

/*********************/

connection_t *connection_or_connect(routerinfo_t *router) {
  connection_t *conn;

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

  if(connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn);
    return NULL;
  }

  switch(connection_connect(conn, router->address, router->addr, router->or_port)) {
    case -1:
      connection_remove(conn);
      connection_free(conn);
      return NULL;
    case 0:
      connection_set_poll_socket(conn);
      connection_watch_events(conn, POLLIN | POLLOUT | POLLERR); 
      /* writable indicates finish, readable indicates broken link,
         error indicates broken link on windows */
#ifdef USE_TLS
      conn->state = OR_CONN_STATE_CONNECTING;
#else
      conn->state = OR_CONN_STATE_CLIENT_CONNECTING;
#endif
      return conn;
    /* case 1: fall through */
  }

  connection_set_poll_socket(conn);

#ifdef USE_TLS
  if(connection_tls_start_handshake(conn, 0) >= 0)
    return conn;
#else
  if((options.OnionRouter && or_handshake_client_send_auth(conn) >= 0) ||
     (!options.OnionRouter && or_handshake_op_send_keys(conn) >= 0))
    return conn; /* success! */
#endif

  /* failure */
  connection_remove(conn);
  connection_free(conn);
  return NULL;
}

/* ********************************** */

#ifndef USE_TLS
/* Helper functions to implement handshaking */

#define FLAGS_LEN 2
#define KEY_LEN 16
#define ADDR_LEN 4
#define PORT_LEN 2
#define PKEY_LEN 128

static int 
or_handshake_op_send_keys(connection_t *conn) {
  unsigned char message[FLAGS_LEN + KEY_LEN + KEY_LEN];
  unsigned char cipher[PKEY_LEN];
  int retval;

  assert(conn && conn->type == CONN_TYPE_OR);

  conn->bandwidth = DEFAULT_BANDWIDTH_OP;

  /* generate random keys */
  if(crypto_cipher_generate_key(conn->f_crypto) ||
     crypto_cipher_generate_key(conn->b_crypto)) {
    log(LOG_ERR,"Cannot generate a secure symmetric key.");
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_op_send_keys() : Generated symmetric keys.");
  /* compose the message */
  *(uint16_t *)(message) = htons(HANDSHAKE_AS_OP);
  memcpy((void *)(message+FLAGS_LEN), 
         (void *)crypto_cipher_get_key(conn->f_crypto), 16);
  memcpy((void *)(message+FLAGS_LEN+KEY_LEN), 
         (void *)crypto_cipher_get_key(conn->b_crypto), 16);

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
           PORT_LEN+KEY_LEN+KEY_LEN];
  char cipher[PKEY_LEN];
  struct sockaddr_in me; /* my router identity */

  assert(conn);

  if(learn_my_address(&me) < 0)
    return -1;

  /* generate random keys */
  if(crypto_cipher_generate_key(conn->f_crypto) ||
     crypto_cipher_generate_key(conn->b_crypto)) {
    log(LOG_ERR,"Cannot generate a secure symmetric key.");
    return -1;
  }
  log(LOG_DEBUG,"or_handshake_client_send_auth() : Generated symmetric keys.");

  /* generate first message */
  *(uint16_t*)buf = htons(HANDSHAKE_AS_OR);
  *(uint32_t*)(buf+FLAGS_LEN) = me.sin_addr.s_addr; /* local address, network order */
  *(uint16_t*)(buf+FLAGS_LEN+ADDR_LEN) = me.sin_port; /* local port, network order */
  *(uint32_t*)(buf+FLAGS_LEN+ADDR_LEN+PORT_LEN) = htonl(conn->addr); /* remote address */
  *(uint16_t*)(buf+FLAGS_LEN+ADDR_LEN+PORT_LEN+ADDR_LEN) = htons(conn->port); /* remote port */
  memcpy(buf+FLAGS_LEN+ADDR_LEN+PORT_LEN+ADDR_LEN+PORT_LEN,
         crypto_cipher_get_key(conn->f_crypto),16); /* keys */
  memcpy(buf+FLAGS_LEN+ADDR_LEN+PORT_LEN+ADDR_LEN+PORT_LEN+KEY_LEN,
         crypto_cipher_get_key(conn->b_crypto),16);
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
  char buf[128]; /* only 52 of this is expected to be used */
  char cipher[128];
  int retval;
  struct sockaddr_in me; /* my router identity */

  assert(conn);

  if(learn_my_address(&me) < 0)
    return -1;

  if(conn->inbuf_datalen < 128) /* entire response available? */
    return 0; /* not yet */

  connection_fetch_from_buf(cipher,128,conn);
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
  else if (retval != 52)
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
  if ( (memcmp(crypto_cipher_get_key(conn->f_crypto), buf+12, 16)) ||/* keys */
       (memcmp(crypto_cipher_get_key(conn->b_crypto), buf+28, 16)) ) {
    log(LOG_ERR,"client_process_auth: Router %s:%u: bad key info.",conn->address,conn->port);
    return -1;
  }

  log(LOG_DEBUG,"or_handshake_client_process_auth() : Response valid.");

  /* reply is just local addr/port, remote addr/port, nonce */
  memcpy(buf+12, buf+44, 8);

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

  routerinfo_t *router;

  assert(conn);

  log(LOG_DEBUG,"or_handshake_server_process_auth() entered.");

  if(conn->inbuf_datalen < 128) /* entire response available? */
    return 0; /* not yet */  

  connection_fetch_from_buf(cipher,128,conn);
  log(LOG_DEBUG,"or_handshake_server_process_auth() : Received auth.");

  /* decrypt response */
  retval = crypto_pk_private_decrypt(get_privatekey(), cipher, 128, buf, RSA_PKCS1_PADDING);
  if (retval == -1) {
    log(LOG_ERR,"or_handshake_server_process_auth: Public-key decryption failed.");
    log(LOG_DEBUG,"or_handshake_server_process_auth() : Reason : %s.",
        crypto_perror());
    return -1;
  }

  if (retval == 46) {

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

    conn->bandwidth = router->bandwidth;

    /* copy all relevant info to conn */
    conn->addr = router->addr, conn->port = router->or_port;
    conn->pkey = crypto_pk_dup_key(router->pkey);
    if(conn->address)
      free(conn->address);
    conn->address = strdup(router->address);

    /* generate a nonce */
    retval = crypto_rand(8, conn->nonce);
    if (retval) { /* error */
      log(LOG_ERR,"Cannot generate a nonce.");
      return -1;
    }
    log(LOG_DEBUG,"or_handshake_server_process_auth(): Nonce generated.");

    memmove(buf, buf+2, 44);
    memcpy(buf+44,conn->nonce,8); /* append the nonce to the end of the message */

    /* encrypt message */
    retval = crypto_pk_public_encrypt(conn->pkey, buf, 52, cipher,RSA_PKCS1_PADDING);
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

  if(retval == 34) {
    log(LOG_DEBUG,"or_handshake_server_process_auth(): Decrypted OP-style auth message.");
    if(ntohs(*(uint16_t*)buf) != HANDSHAKE_AS_OP) {
      log(LOG_DEBUG,"or_handshake_server_process_auth(): ...but wasn't labelled OP. Dropping.");
      return -1;
    }

    crypto_cipher_set_key(conn->b_crypto, buf+2);
    crypto_cipher_set_key(conn->f_crypto, buf+18);

    memset(iv, 0, 16);
    crypto_cipher_set_iv(conn->b_crypto, iv);
    crypto_cipher_set_iv(conn->f_crypto, iv);

    crypto_cipher_encrypt_init_cipher(conn->b_crypto);
    crypto_cipher_decrypt_init_cipher(conn->f_crypto);

    conn->state = OR_CONN_STATE_OPEN;
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

  connection_fetch_from_buf(cipher,128,conn);
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
#endif

int connection_write_cell_to_buf(const cell_t *cellp, connection_t *conn) {
  char networkcell[CELL_NETWORK_SIZE];
  char *n = networkcell;

  cell_pack(n, cellp);
 
#ifndef USE_TLS
  if(connection_encrypt_cell(n,conn)<0) {
    return -1;
  }
#endif
 
  return connection_write_to_buf(n, CELL_NETWORK_SIZE, conn);
}

int connection_process_cell_from_inbuf(connection_t *conn) {
  /* check if there's a whole cell there.
   *    * if yes, pull it off, decrypt it if we're not doing TLS, and process it.
   *       */
#ifndef USE_TLS
  char networkcell[CELL_NETWORK_SIZE];
#endif
  char buf[CELL_NETWORK_SIZE];
//  int x;
  cell_t cell;
 
  if(conn->inbuf_datalen < CELL_NETWORK_SIZE) /* entire response available? */
    return 0; /* not yet */
 
#ifdef USE_TLS
  connection_fetch_from_buf(buf, CELL_NETWORK_SIZE, conn);
#else
  connection_fetch_from_buf(networkcell, CELL_NETWORK_SIZE, conn);
#if 0
  printf("Cell header crypttext: ");
  for(x=0;x<8;x++) {
    printf("%u ",crypted[x]);
  }
  printf("\n");
#endif
  /* decrypt */
  if(crypto_cipher_decrypt(conn->b_crypto, networkcell, CELL_NETWORK_SIZE, buf)) {
    log_fn(LOG_ERR,"Decryption failed, dropping.");
    return connection_process_inbuf(conn); /* process the remainder of the buffer */
  }
//  log_fn(LOG_DEBUG,"Cell decrypted (%d bytes).",outlen);
#if 0
  printf("Cell header plaintext: ");
  for(x=0;x<8;x++) {
    printf("%u ",outbuf[x]);
  }
  printf("\n");
#endif
#endif
 
  /* retrieve cell info from buf (create the host-order struct from the network-order string) */
  cell_unpack(&cell, buf);
 
//  log_fn(LOG_DEBUG,"Decrypted cell is of type %u (ACI %u).",cellp->command,cellp->aci);
  command_process_cell(&cell, conn);
 
  return connection_process_inbuf(conn); /* process the remainder of the buffer */
}


#ifndef USE_TLS
int connection_encrypt_cell(char *cellp, connection_t *conn) {
  char cryptcell[CELL_NETWORK_SIZE];
#if 0
  int x;
  char *px;
 
  printf("Sending: Cell header plaintext: ");
  px = (char *)cellp;
  for(x=0;x<8;x++) {
    printf("%u ",px[x]);
  }#
  printf("\n");
#endif
 
  assert(conn);
 
  if(crypto_cipher_encrypt(conn->f_crypto, cellp, CELL_NETWORK_SIZE, cryptcell)) {
    log(LOG_ERR,"Could not encrypt cell for connection %s:%u.",conn->address,conn->port);
    return -1;
  }
#if 0
  printf("Sending: Cell header crypttext: ");
  px = (char *)&newcell;
  for(x=0;x<8;x++) {
    printf("%u ",px[x]);
  }
  printf("\n");
#endif

  memcpy(cellp,cryptcell,CELL_NETWORK_SIZE);
  return 0;
}
#endif



/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
