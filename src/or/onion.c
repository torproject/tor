/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

static int onion_process(circuit_t *circ);
static int onion_deliver_to_conn(aci_t aci, unsigned char *onion, uint32_t onionlen, connection_t *conn);
static int count_acceptable_routers(routerinfo_t **rarray, int rarray_len);
static int find_tracked_onion(unsigned char *onion, uint32_t onionlen);

int decide_aci_type(uint32_t local_addr, uint16_t local_port,
                    uint32_t remote_addr, uint16_t remote_port) {

  if(local_addr > remote_addr)
    return ACI_TYPE_HIGHER;
  if(local_addr < remote_addr)
    return ACI_TYPE_LOWER;
  if(local_port > remote_port)
    return ACI_TYPE_HIGHER;
   /* else */
   return ACI_TYPE_LOWER; 
}

/* global (within this file) variables used by the next few functions */
static struct onion_queue_t *ol_list=NULL;
static struct onion_queue_t *ol_tail=NULL;
static int ol_length=0;

int onion_pending_add(circuit_t *circ) {
  struct onion_queue_t *tmp;

  tmp = malloc(sizeof(struct onion_queue_t));
  memset(tmp, 0, sizeof(struct onion_queue_t));
  tmp->circ = circ;

  if(!ol_tail) {
    assert(!ol_list);
    assert(!ol_length);
    ol_list = tmp;
    ol_tail = tmp;
    ol_length++;
    return 0;
  }

  assert(ol_list);
  assert(!ol_tail->next);

  if(ol_length >= options.MaxOnionsPending) {
    log(LOG_INFO,"onion_pending_add(): Already have %d onions queued. Closing.", ol_length);
    free(tmp);
    return -1;
  }

  ol_length++;
  ol_tail->next = tmp;
  ol_tail = tmp;
  return 0;

}

int onion_pending_check(void) {
  if(ol_list)
    return 1;
  else
    return 0;
}

void onion_pending_process_one(void) {
  struct data_queue_t *tmpd;
  circuit_t *circ; 

  if(!ol_list)
    return; /* no onions pending, we're done */

  assert(ol_list->circ && ol_list->circ->p_conn);
  assert(ol_length > 0);
  circ = ol_list->circ;

  if(onion_process(circ) < 0) {
    log(LOG_DEBUG,"onion_pending_process_one(): Failed. Closing.");
    onion_pending_remove(circ);
    circuit_close(circ);
  } else {
    log(LOG_DEBUG,"onion_pending_process_one(): Succeeded. Delivering queued data cells.");
    for(tmpd = ol_list->data_cells; tmpd; tmpd=tmpd->next) {
      command_process_data_cell(tmpd->cell, circ->p_conn); 
    }
    onion_pending_remove(circ);
  }
  return;
}

/* go through ol_list, find the onion_queue_t element which points to
 * circ, remove and free that element. leave circ itself alone.
 */
void onion_pending_remove(circuit_t *circ) {
  struct onion_queue_t *tmpo, *victim;
  struct data_queue_t *tmpd;

  if(!ol_list)
    return; /* nothing here. */

  /* first check to see if it's the first entry */
  tmpo = ol_list;
  if(tmpo->circ == circ) {
    /* it's the first one. remove it from the list. */
    ol_list = tmpo->next;
    if(!ol_list)
      ol_tail = NULL;
    ol_length--;
    victim = tmpo;
  } else { /* we need to hunt through the rest of the list */
    for( ;tmpo->next && tmpo->next->circ != circ; tmpo=tmpo->next) ;
    if(!tmpo->next) {
      log(LOG_WARNING,"onion_pending_remove(): circ (p_aci %d), not in list!",circ->p_aci);
      return;
    }
    /* now we know tmpo->next->circ == circ */
    victim = tmpo->next;
    tmpo->next = victim->next;
    if(ol_tail == victim)
      ol_tail = tmpo;
    ol_length--;
  }

  /* now victim points to the element that needs to be removed */

  /* first dump the attached data cells too, if any */
  while(victim->data_cells) {
    tmpd = victim->data_cells;
    victim->data_cells = tmpd->next;
    free(tmpd->cell);
    free(tmpd);
  }
 
  free(victim); 

}

struct data_queue_t *data_queue_add(struct data_queue_t *list, cell_t *cell) {
  struct data_queue_t *tmpd, *newd;

  newd = malloc(sizeof(struct data_queue_t));
  memset(newd, 0, sizeof(struct data_queue_t));
  newd->cell = malloc(sizeof(cell_t));
  memcpy(newd->cell, cell, sizeof(cell_t));

  if(!list) {
    return newd;
  }
  for(tmpd = list; tmpd->next; tmpd=tmpd->next) ;
  /* now tmpd->next is null */
  tmpd->next = newd;
  return list;
}

/* a data cell has arrived for a circuit which is still pending. Find
 * the right entry in ol_list, and add it to the end of the 'data_cells'
 * list.
 */
void onion_pending_data_add(circuit_t *circ, cell_t *cell) {
  struct onion_queue_t *tmpo;

  for(tmpo=ol_list; tmpo; tmpo=tmpo->next) {
    if(tmpo->circ == circ) {
      tmpo->data_cells = data_queue_add(tmpo->data_cells, cell);
      return;
    }
  }
}

/* helper function for onion_process */
static int onion_deliver_to_conn(aci_t aci, unsigned char *onion, uint32_t onionlen, connection_t *conn) {
  char *buf;
  int buflen, dataleft;
  cell_t cell;
 
  assert(aci && onion && onionlen);
 
  buflen = onionlen+4;
  buf = malloc(buflen);
  if(!buf)
    return -1;
 
  log(LOG_DEBUG,"onion_deliver_to_conn(): Setting onion length to %u.",onionlen);
  *(uint32_t*)buf = htonl(onionlen);
  memcpy((buf+4),onion,onionlen);
 
  dataleft = buflen;
  while(dataleft > 0) {
    memset(&cell,0,sizeof(cell_t));
    cell.command = CELL_CREATE;
    cell.aci = aci;
    if(dataleft >= CELL_PAYLOAD_SIZE)
      cell.length = CELL_PAYLOAD_SIZE;
    else
      cell.length = dataleft;
    memcpy(cell.payload, buf+buflen-dataleft, cell.length);
    dataleft -= cell.length;
 
    log(LOG_DEBUG,"onion_deliver_to_conn(): Delivering create cell, payload %d bytes.",cell.length);
    if(connection_write_cell_to_buf(&cell, conn) < 0) {
      log(LOG_DEBUG,"onion_deliver_to_conn(): Could not buffer new create cells. Closing.");
      free(buf);
      return -1;
    }
  }
  free(buf);
  return 0;
}

static int onion_process(circuit_t *circ) {
  connection_t *n_conn;
  int retval;
  aci_t aci_type;
  struct sockaddr_in me; /* my router identity */
  onion_layer_t layer;

  if(learn_my_address(&me) < 0)
    return -1;

  /* decrypt it in-place */
  if(decrypt_onion(circ->onion,circ->onionlen,getprivatekey(),&layer) < 0) {
    log(LOG_DEBUG,"command_process_create_cell(): decrypt_onion() failed, closing circuit.");
    return -1;
  }
  log(LOG_DEBUG,"command_process_create_cell(): Onion decrypted.");

  /* check freshness */
  if (layer.expire < (uint32_t)time(NULL)) /* expired onion */ /*XXXX*/
  { 
    log(LOG_NOTICE,"I have just received an expired onion. This could be a replay attack.");
    return -1;
  }

  aci_type = decide_aci_type(ntohl(me.sin_addr.s_addr), ntohs(me.sin_port),
                             layer.addr, layer.port);
      
  if(circuit_init(circ, aci_type, &layer) < 0) { 
    log(LOG_ERR,"process_onion(): init_circuit() failed.");
    return -1;
  }

  /* check for replay. at the same time, add it to the pile of tracked onions. */
  if(find_tracked_onion(circ->onion, circ->onionlen)) {
    log(LOG_NOTICE,"process_onion(): I have just received a replayed onion. This could be a replay attack.");
    return -1;
  }

  /* now we must send create cells to the next router */
  if(circ->n_addr && circ->n_port) {
    n_conn = connection_twin_get_by_addr_port(circ->n_addr,circ->n_port);
    if(!n_conn || n_conn->type != CONN_TYPE_OR) {
      /* i've disabled making connections through OPs, but it's definitely
       * possible here. I'm not sure if it would be a bug or a feature. -RD
       */
      /* note also that this will close circuits where the onion has the same
       * router twice in a row in the path. i think that's ok. -RD
       */
      log(LOG_DEBUG,"command_process_create_cell(): Next router not connected. Closing.");
      return -1;
    }

    circ->n_addr = n_conn->addr; /* these are different if we found a twin instead */
    circ->n_port = n_conn->port;

    circ->n_conn = n_conn;
    log(LOG_DEBUG,"command_process_create_cell(): n_conn is %s:%u",n_conn->address,n_conn->port);

    /* send the CREATE cells on to the next hop  */
    pad_onion(circ->onion, circ->onionlen, ONION_LAYER_SIZE);
    log(LOG_DEBUG,"command_process_create_cell(): Padded the onion with random data.");

    retval = onion_deliver_to_conn(circ->n_aci, circ->onion, circ->onionlen, n_conn); 
    free(circ->onion);
    circ->onion = NULL;
    if (retval == -1) {
      log(LOG_DEBUG,"command_process_create_cell(): Could not deliver the onion to next conn. Closing.");
      return -1;
    }
  } else { /* this is destined for an exit */
    log(LOG_DEBUG,"command_process_create_cell(): create cell reached exit. Circuit established.");
#if 0
    log(LOG_DEBUG,"command_process_create_cell(): Creating new exit connection.");
    n_conn = connection_new(CONN_TYPE_EXIT);
    if(!n_conn) {
      log(LOG_DEBUG,"command_process_create_cell(): connection_new failed. Closing.");
      return -1;
    }
    n_conn->state = EXIT_CONN_STATE_CONNECTING_WAIT;
    n_conn->receiver_bucket = -1; /* edge connections don't do receiver buckets */
    n_conn->bandwidth = -1;
    n_conn->s = -1; /* not yet valid */
    if(connection_add(n_conn) < 0) { /* no space, forget it */
      log(LOG_DEBUG,"command_process_create_cell(): connection_add failed. Closing.");
      connection_free(n_conn);
      return -1;
    }
    circ->n_conn = n_conn;
#endif
  }
  return 0;
}

/* uses a weighted coin with weight cw to choose a route length */
int chooselen(double cw)
{
  int len = 2;
  int retval = 0;
  unsigned char coin;
  
  if ((cw < 0) || (cw >= 1)) /* invalid parameter */
    return -1;
  
  while(1)
  {
    retval = crypto_pseudo_rand(1, &coin);
    if (retval)
      return -1;
    
    if (coin > cw*255) /* don't extend */
      break;
    else
      len++;
  }
  
  return len;
}

/* returns an array of pointers to routent that define a new route through the OR network
 * int cw is the coin weight to use when choosing the route 
 * order of routers is from last to first
 */
unsigned int *new_route(double cw, routerinfo_t **rarray, int rarray_len, int *routelen)
{
  int i;
  int num_acceptable_routers;
  unsigned int *route;
  unsigned int oldchoice, choice;

  assert((cw >= 0) && (cw < 1) && (rarray) && (routelen) ); /* valid parameters */

  *routelen = chooselen(cw);
  if (*routelen == -1) {
    log(LOG_ERR,"Choosing route length failed.");
    return NULL;
  }
  log(LOG_DEBUG,"new_route(): Chosen route length %d.",*routelen);

  num_acceptable_routers = count_acceptable_routers(rarray, rarray_len);

  if(num_acceptable_routers < 2) {
    log(LOG_INFO,"new_route(): Not enough acceptable routers. Failing.");
    return NULL;
  }

  if(num_acceptable_routers < *routelen) {
    log(LOG_DEBUG,"new_route(): Cutting routelen from %d to %d.",*routelen, num_acceptable_routers);
    *routelen = num_acceptable_routers;
  }

  if(*routelen < 1) {
    log(LOG_ERR,"new_route(): Didn't find any acceptable routers. Failing.");
    return NULL;
  }

  /* allocate memory for the new route */
  route = (unsigned int *)malloc(*routelen * sizeof(unsigned int));
  if (!route) {
    log(LOG_ERR,"Memory allocation failed.");
    return NULL;
  }
 
  oldchoice = rarray_len;
  for(i=0;i<*routelen;i++) {
    log(LOG_DEBUG,"new_route(): Choosing hop %u.",i);
    if(crypto_pseudo_rand(sizeof(unsigned int),(unsigned char *)&choice)) {
      free((void *)route);
      return NULL;
    }

    choice = choice % (rarray_len);
    log(LOG_DEBUG,"new_route(): Contemplating router %u.",choice);
    if(choice == oldchoice ||
      (oldchoice < rarray_len && !crypto_pk_cmp_keys(rarray[choice]->pkey, rarray[oldchoice]->pkey)) ||
      (options.ORPort && !connection_twin_get_by_addr_port(rarray[choice]->addr, rarray[choice]->or_port))) {
      /* Same router as last choice, or router twin,
       *   or no routers with that key are connected to us.
       * Try again. */
      log(LOG_DEBUG,"new_route(): Picked a router %d that won't work as next hop.",choice);
      i--;
      continue;  
    }
    log(LOG_DEBUG,"new_route(): Chosen router %u for hop %u.",choice,i);
    oldchoice = choice;
    route[i] = choice;
  }
   
  return route;
}

static int count_acceptable_routers(routerinfo_t **rarray, int rarray_len) {
  int i, j;
  int num=0;
  connection_t *conn;

  for(i=0;i<rarray_len;i++) {
    log(LOG_DEBUG,"Contemplating whether router %d is a new option...",i);
    if(options.ORPort) {
      conn = connection_exact_get_by_addr_port(rarray[i]->addr, rarray[i]->or_port);
      if(!conn || conn->type != CONN_TYPE_OR || conn->state != OR_CONN_STATE_OPEN) {
        log(LOG_DEBUG,"Nope, %d is not connected.",i);
        goto next_i_loop;
      }
    }
    for(j=0;j<i;j++) {
      if(!crypto_pk_cmp_keys(rarray[i]->pkey, rarray[j]->pkey)) {
        /* these guys are twins. so we've already counted him. */
        log(LOG_DEBUG,"Nope, %d is a twin of %d.",i,j);
        goto next_i_loop;
      }
    }
    num++;
    log(LOG_DEBUG,"I like %d. num_acceptable_routers now %d.",i, num);
    next_i_loop:
      ; /* our compiler may need an explicit statement after the label */
  }

  return num;
}

/* creates a new onion from route, stores it and its length into buf and len respectively */
unsigned char *create_onion(routerinfo_t **rarray, int rarray_len, unsigned int *route, int routelen, int *len, crypt_path_t **cpath)
{
  int i,j;
  char *layerp;
  crypt_path_t *hop = NULL;
  unsigned char *buf;
  routerinfo_t *router;
  unsigned char iv[16];
  struct in_addr netaddr;
  onion_layer_t layer;

  assert(rarray && route && len && routelen);

  /* calculate the size of the onion */
  *len = routelen * ONION_LAYER_SIZE + ONION_PADDING_SIZE;
  /* 28 bytes per layer + 100 bytes padding for the innermost layer */
  log(LOG_DEBUG,"create_onion() : Size of the onion is %u.",*len);
    
  /* allocate memory for the onion */
  buf = malloc(*len);
  if(!buf) {
    log(LOG_ERR,"Error allocating memory.");
    return NULL;
  }
  log(LOG_DEBUG,"create_onion() : Allocated memory for the onion.");
    
  for(i=0; i<routelen; i++) {
    netaddr.s_addr = htonl((rarray[route[i]])->addr);

    log(LOG_DEBUG,"create_onion(): %u : %s:%u, %u/%u",routelen-i,
        inet_ntoa(netaddr),
        (rarray[route[i]])->or_port,
        (rarray[route[i]])->pkey,
        crypto_pk_keysize((rarray[route[i]])->pkey));
  }
    
  layerp = buf + *len - ONION_LAYER_SIZE - ONION_PADDING_SIZE; /* pointer to innermost layer */
  /* create the onion layer by layer, starting with the innermost */
  for (i=0;i<routelen;i++) {
    router = rarray[route[i]];
      
//      log(LOG_DEBUG,"create_onion() : %u",router);
//      log(LOG_DEBUG,"create_onion() : This router is %s:%u",inet_ntoa(*((struct in_addr *)&router->addr)),router->or_port);
//      log(LOG_DEBUG,"create_onion() : Key pointer = %u.",router->pkey);
//      log(LOG_DEBUG,"create_onion() : Key size = %u.",crypto_pk_keysize(router->pkey)); 
    

    layer.version = OR_VERSION;
    if (i) /* not last hop */
      layer.port = rarray[route[i-1]]->or_port;
    else
      layer.port = 0;

    /* Dest Addr */
    if (i) /* not last hop */
      layer.addr = rarray[route[i-1]]->addr;
    else
      layer.addr = 0;

    /* Expiration Time */
    layer.expire = (uint32_t)(time(NULL) + 86400); /* NOW + 1 day */
  
    /* Key Seed Material */
    if(crypto_rand(ONION_KEYSEED_LEN, layer.keyseed)) { /* error */
      log(LOG_ERR,"Error generating random data.");
      goto error;
    }

    onion_pack(layerp, &layer);

//      log(LOG_DEBUG,"create_onion() : Onion layer %u built : %u, %u, %u, %s, %u.",i+1,layer->zero,layer->backf,layer->forwf,inet_ntoa(*((struct in_addr *)&layer->addr)),layer->port);
      
    /* build up the crypt_path */
    if(cpath) {
      cpath[i] = (crypt_path_t *)malloc(sizeof(crypt_path_t));
      if(!cpath[i]) {
        log(LOG_ERR,"Error allocating memory.");
        goto error;
      }
      
      log(LOG_DEBUG,"create_onion() : Building hop %u of crypt path.",i+1);
      hop = cpath[i];

      /* calculate keys */
      crypto_SHA_digest(layer.keyseed,16,hop->digest3);
      log(LOG_DEBUG,"create_onion() : First SHA pass performed.");
      crypto_SHA_digest(hop->digest3,20,hop->digest2);
      log(LOG_DEBUG,"create_onion() : Second SHA pass performed.");
      crypto_SHA_digest(hop->digest2,20,hop->digest3);
      log(LOG_DEBUG,"create_onion() : Third SHA pass performed.");
      log(LOG_DEBUG,"create_onion() : Keys generated.");
      /* set IV to zero */
      memset((void *)iv,0,16);

      /* initialize cipher engines */
      if (! (hop->f_crypto = 
             crypto_create_init_cipher(DEFAULT_CIPHER, hop->digest3, iv, 1))) {
        /* cipher initialization failed */
        log(LOG_ERR,"Could not create a crypto environment.");
        goto error;
      }

      if (! (hop->b_crypto = 
             crypto_create_init_cipher(DEFAULT_CIPHER, hop->digest2, iv, 0))) {
        /* cipher initialization failed */
        log(LOG_ERR,"Could not create a crypto environment.");
        goto error;
      }
 
      log(LOG_DEBUG,"create_onion() : Built corresponding crypt path hop.");
    }
      
    /* padding if this is the innermost layer */
    if (!i) {
      if (crypto_pseudo_rand(ONION_PADDING_SIZE, layerp + ONION_LAYER_SIZE)) { /* error */
        log(LOG_ERR,"Error generating pseudo-random data.");
        goto error;
      }
      log(LOG_DEBUG,"create_onion() : This is the innermost layer. Adding 100 bytes of padding.");
    }
      
    /* encrypt */

    if(encrypt_onion(layerp,ONION_PADDING_SIZE+(i+1)*ONION_LAYER_SIZE,router->pkey,layer.keyseed) < 0) {
      log(LOG_ERR,"Error encrypting onion layer.");
      goto error;
    }
    log(LOG_DEBUG,"create_onion() : Encrypted layer.");
      
    /* calculate pointer to next layer */
    layerp = buf + (routelen-i-2)*ONION_LAYER_SIZE;
  }

  return buf;

 error:
  if (buf)
    free(buf);
  if (cpath) {
    for (j=0;j<i;j++) {
      if(cpath[i]->f_crypto)
        crypto_free_cipher_env(cpath[i]->f_crypto);
      if(cpath[i]->b_crypto)
        crypto_free_cipher_env(cpath[i]->b_crypto);
      free((void *)cpath[i]);
    }
  }
  return NULL;
}

/* encrypts 128 bytes of the onion with the specified public key, the rest with 
 * DES OFB with the key as defined in the outter layer */
int encrypt_onion(unsigned char *onion, uint32_t onionlen, crypto_pk_env_t *pkey, char* keyseed) {
  unsigned char *tmpbuf = NULL; /* temporary buffer for crypto operations */
  unsigned char digest[20]; /* stores SHA1 output - 160 bits */
  unsigned char iv[8];
  
  crypto_cipher_env_t *crypt_env = NULL; /* crypto environment */
 
  assert(onion && pkey);
  assert(onionlen >= 128);

  memset(iv,0,8);
    
//  log(LOG_DEBUG,"Onion layer : %u, %u, %u, %s, %u.",onion->zero,onion->backf,onion->forwf,inet_ntoa(*((struct in_addr *)&onion->addr)),onion->port);
  /* allocate space for tmpbuf */
  tmpbuf = (unsigned char *)malloc(onionlen);
  if(!tmpbuf) {
    log(LOG_ERR,"Could not allocate memory.");
    return -1;
  }
  log(LOG_DEBUG,"encrypt_onion() : allocated %u bytes of memory for the encrypted onion (at %u).",onionlen,tmpbuf);
  
  /* get key1 = SHA1(KeySeed) */
  if (crypto_SHA_digest(keyseed,16,digest)) {
    log(LOG_ERR,"Error computing SHA1 digest.");
    goto error;
  }
  log(LOG_DEBUG,"encrypt_onion() : Computed DES key.");
    
  log(LOG_DEBUG,"encrypt_onion() : Trying to RSA encrypt.");
  /* encrypt 128 bytes with RSA *pkey */
  if (crypto_pk_public_encrypt(pkey, onion, 128, tmpbuf, RSA_NO_PADDING) == -1) {
    log(LOG_ERR,"Error RSA-encrypting data :%s",crypto_perror());
    goto error;
  }

  log(LOG_DEBUG,"encrypt_onion() : RSA encrypted first 128 bytes of the onion."); 
    
  /* now encrypt the rest with 3DES OFB */
  crypt_env = crypto_create_init_cipher(CRYPTO_CIPHER_3DES, digest, iv, 1);
  if (!crypt_env) {
    log(LOG_ERR,"Error creating the crypto environment.");
    goto error;
  }
    
  if (crypto_cipher_encrypt(crypt_env,onion+128, onionlen-128, (unsigned char *)tmpbuf+128)) { /* error */
    log(LOG_ERR,"Error performing DES encryption:%s",crypto_perror()); 
    goto error;
  }
  log(LOG_DEBUG,"encrypt_onion() : 3DES OFB encrypted the rest of the onion.");
    
  /* now copy tmpbuf to onion */
  memcpy(onion,tmpbuf,onionlen);
  log(LOG_DEBUG,"encrypt_onion() : Copied cipher to original onion buffer.");
  free(tmpbuf);
  crypto_free_cipher_env(crypt_env);
  return 0;

 error:
  if (tmpbuf)
    free(tmpbuf);
  if (crypt_env)
    crypto_free_cipher_env(crypt_env);
  return -1;
}

/* decrypts the first 128 bytes using RSA and prkey, decrypts the rest with DES OFB with key1 */
int decrypt_onion(unsigned char *onion, uint32_t onionlen, crypto_pk_env_t *prkey, onion_layer_t *layer) {
  void *tmpbuf = NULL; /* temporary buffer for crypto operations */
  unsigned char digest[20]; /* stores SHA1 output - 160 bits */
  unsigned char iv[8];
  
  crypto_cipher_env_t *crypt_env =NULL; /* crypto environment */
  
  assert(onion && prkey);

  memset(iv,0,8);
    
  /* allocate space for tmpbuf */
  tmpbuf = malloc(onionlen);
  if (!tmpbuf) {
    log(LOG_ERR,"Could not allocate memory.");
    return -1;
  }
  log(LOG_DEBUG,"decrypt_onion() : Allocated memory for the temporary buffer.");

  /* decrypt 128 bytes with RSA *prkey */
  if (crypto_pk_private_decrypt(prkey, onion, 128, tmpbuf, RSA_NO_PADDING) == -1)
  {
    log(LOG_ERR,"Error RSA-decrypting data :%s",crypto_perror());
    goto error;
  }
  log(LOG_DEBUG,"decrypt_onion() : RSA decryption complete.");
    
  onion_unpack(layer, tmpbuf);

  /* get key1 = SHA1(KeySeed) */
  if (crypto_SHA_digest(layer->keyseed,16,digest)) {
    log(LOG_ERR,"Error computing SHA1 digest.");
    goto error;
  }
  log(LOG_DEBUG,"decrypt_onion() : Computed DES key.");
    
  /* now decrypt the rest with 3DES OFB */
  crypt_env = crypto_create_init_cipher(CRYPTO_CIPHER_3DES, digest, iv, 0);
  if (!crypt_env) {
    log(LOG_ERR,"Error creating crypto environment");
    goto error;
  }
 
  if (crypto_cipher_decrypt(crypt_env,onion+128, onionlen-128,tmpbuf+128)) {
    log(LOG_ERR,"Error performing DES decryption:%s",crypto_perror());
    goto error;
  }
    
  log(LOG_DEBUG,"decrypt_onion() : DES decryption complete.");
    
  /* now copy tmpbuf to onion */
  memcpy(onion,tmpbuf,onionlen);
  free(tmpbuf);
  crypto_free_cipher_env(crypt_env);
  return 0;

 error:
  if (tmpbuf)
    free(tmpbuf);
  if (crypt_env)
    crypto_free_cipher_env(crypt_env);
  return -1;
}

/* delete first n bytes of the onion and pads the end with n bytes of random data */
void pad_onion(unsigned char *onion, uint32_t onionlen, int n)
{
  assert(onion);

  memmove(onion,onion+n,onionlen-n);
  crypto_pseudo_rand(n, onion+onionlen-n);
}




/* red black tree using Niels' tree.h. I used
http://www.openbsd.org/cgi-bin/cvsweb/src/regress/sys/sys/tree/rb/
as my guide */

#include "tree.h"

struct tracked_onion { 
  RB_ENTRY(tracked_onion) node;
  uint32_t expire;
  char digest[20]; /* SHA digest of the onion */
  struct tracked_onion *next;
};

RB_HEAD(tracked_tree, tracked_onion) tracked_root;

int compare_tracked_onions(struct tracked_onion *a, struct tracked_onion *b) {
  return memcmp(a->digest, b->digest, 20);
}

RB_PROTOTYPE(tracked_tree, tracked_onion, node, compare_tracked_onions)
RB_GENERATE(tracked_tree, tracked_onion, node, compare_tracked_onions)

void init_tracked_tree(void) {
  RB_INIT(&tracked_root);
}

/* see if this onion has been seen before. if so, return 1, else
 * return 0 and add the sha1 of this onion to the tree.
 */
static int find_tracked_onion(unsigned char *onion, uint32_t onionlen) {
  static struct tracked_onion *head_tracked_onions = NULL; /* linked list of tracked onions */
  static struct tracked_onion *tail_tracked_onions = NULL;

  uint32_t now = time(NULL); 
  struct tracked_onion *to;

  /* first take this opportunity to see if there are any expired
   * onions in the tree. we know this is fast because the linked list
   * 'tracked_onions' is ordered by when they were seen.
   */
  while(head_tracked_onions && (head_tracked_onions->expire < now)) {
    to = head_tracked_onions;
    log(LOG_DEBUG,"find_tracked_onion(): Forgetting old onion (expires %d)", to->expire);
    head_tracked_onions = to->next;
    if(!head_tracked_onions)          /* if there are no more, */
      tail_tracked_onions = NULL; /* then make sure the list's tail knows that too */
    RB_REMOVE(tracked_tree, &tracked_root, to);
    free(to);
  }

  to = malloc(sizeof(struct tracked_onion));
  
  /* compute the SHA digest of the onion */
  crypto_SHA_digest(onion, onionlen, to->digest);

  /* try adding it to the tree. if it's already there it will return it. */
  if(RB_INSERT(tracked_tree, &tracked_root, to)) {
    /* yes, it's already there: this is a replay. */
    free(to);
    return 1;
  }
  
  /* this is a new onion. add it to the list. */

  to->expire = ntohl(*(uint32_t *)(onion+7)); /* set the expiration date */
  to->next = NULL;

  if (!head_tracked_onions) {
    head_tracked_onions = to;
  } else {
    tail_tracked_onions->next = to;
  }
  tail_tracked_onions = to;

  log(LOG_DEBUG,"find_tracked_onion(): Remembered new onion (expires %d)", to->expire);
 
  return 0;
}

void
onion_pack(char *dest, onion_layer_t *src)
{
  assert((src->version & 0x80) == 0);
  
  *(uint8_t*)(dest) = src->version;
  *(uint16_t*)(dest+1) = htons(src->port);
  *(uint32_t*)(dest+3) = htonl(src->addr);
  *(uint32_t*)(dest+7) = htonl(src->expire);
  memcpy(dest+11, src->keyseed, ONION_KEYSEED_LEN);
  log(LOG_DEBUG,"onion_pack(): version %d, port %d, addr %s, expire %u", src->version, src->port,
    inet_ntoa(*((struct in_addr *)(dest+3))), src->expire);
}

void
onion_unpack(onion_layer_t *dest, char *src)
{
  dest->version = *(uint8_t*)src;
  dest->port = ntohs(*(uint16_t*)(src+1));
  dest->addr = ntohl(*(uint32_t*)(src+3));
  dest->expire = ntohl(*(uint32_t*)(src+7));
  memcpy(dest->keyseed, src+11, ONION_KEYSEED_LEN);

  log(LOG_DEBUG,"onion_unpack(): version %d, port %d, addr %s, expire %u", dest->version, dest->port,
    inet_ntoa(*((struct in_addr *)(src+3))), dest->expire);
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
